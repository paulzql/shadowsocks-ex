defmodule Shadowsocks.Conn.ObfsServer do
    alias Shadowsocks.Stream
    @behaviour  Shadowsocks.Conn
    @timeout 10000
    @weeks %{1=>"Mon",2=>"Tues",3=>"Wed",4=>"Thur",5=>"Fri",6=>"Sat",7=>"Sun"}
    @months %{1=>"Jan",2=>"Feb",3=>"Mar",4=>"Apr",5=>"May",6=>"Jun",
              7=>"Jul",8=>"Aug",9=>"Sep",10=>"Oct",11=>"Nov",12=>"Dec"}

    def init(socket, encoder, parent, args) do
        case Stream.recv(socket, 6, @timeout) do
            {:ok, _, <<"GET ",_::binary>>=data} ->
                init_http(socket, encoder, parent, args, data)
            {:ok, _, <<"POST ",_::binary>>=data} ->
                init_http(socket, encoder, parent, args, data)
            {:ok, _, <<"PUT ",_::binary>>=data} ->
                init_http(socket, encoder, parent, args, data)
            {:ok, _, data} ->
                init_normal(socket, encoder, parent, args, data)
            _ ->
                :ignore
        end
    end

    defp init_http(socket, encoder, parent, args, rest) do
      case recv_header(socket, rest, 0) do
        {:ok, header, rest} ->
          case :binary.match(header, "Upgrade: websocket\r\n") do
            :nomatch ->
              send_bad_request(socket, parent)
            _ ->
            try do
              Shadowsocks.Protocol.init_stream!(socket, encoder, rest)
              |> Shadowsocks.Protocol.recv_target()
            rescue e ->
              {:error, e}
            end
            |> case do
              {:error, _error} ->
                send_bad_request(socket, parent)
              {stream, addr} ->
                ssock = Shadowsocks.Conn.connect!(addr, args)
                send_http_header(socket, parent)
                proxy_stream(stream, parent, ssock)
            end
          end
        {:error, _} ->
          send_bad_request(socket, parent)
          # ignore when remote closed
          :ignore
      end
    end
    defp recv_header(_socket, rest, index) when index > 1024 do
      {:error, rest}
    end
    defp recv_header(socket, rest, 0) do
      with {:ok, _, data} <- Stream.recv(socket, 0, @timeout),
           new_data <- <<rest::binary, data::binary>> do
           case :binary.match(new_data, "\r\n") do
             :nomatch ->
               recv_header(socket, rest, 0)
             {index, 2} ->
               recv_header(socket, new_data, index+2)
           end
      else
        _ ->
        {:error, rest}
      end
    end
    defp recv_header(socket, rest, index) do
      case :binary.match(rest, "\r\n", scope: {index, byte_size(rest)-index}) do
        {^index, 2} ->
          header_len = index+2
          <<header::binary-size(header_len), rest::binary>> = rest
          {:ok, header, rest}
        {new_index, 2} ->
          recv_header(socket, rest, new_index+2)
        :nomatch ->
          with {:ok, _, data} <- Stream.recv(socket, 0, @timeout),
               new_data <- <<rest::binary, data::binary>> do
               recv_header(socket, new_data, index)
          else
            _ ->
            {:error, rest}
          end
      end
    end

    defp init_normal(socket, encoder, parent, args, rest) do
        {stream, addr} =
        Shadowsocks.Protocol.init_stream!(socket, encoder, rest)
        |> Shadowsocks.Protocol.recv_target()
        ssock = Shadowsocks.Conn.connect!(addr, args)
        proxy_stream(stream, parent, ssock)
    end

    defp proxy_stream(%Stream{}=stream, parent, ssock) do
      conn_pid = self()
      pid = spawn(fn ->
      stream
      |> Shadowsocks.Protocol.send_iv!()
      |> Shadowsocks.Conn.proxy_stream(ssock, parent, 0, :up, conn_pid)
      end)

      Shadowsocks.Conn.proxy_stream(ssock, %Stream{stream | ota: false}, parent, 0, :down, conn_pid)
      ref = Process.monitor(pid)
      receive do
      {:DOWN, ^ref, _, _, _} ->
          :ok
      after 1000 ->
          :ok
      end
    end
    defp proxy_stream(socket, _parent, ssock) when is_port(socket) do
      pid = spawn(fn ->
         proxy_stream(socket, ssock)
      end)
      proxy_stream(ssock, socket)
      ref = Process.monitor(pid)
      receive do
      {:DOWN, ^ref, _, _, _} ->
          :ok
      after 1000 ->
          :ok
      end
    end
    defp proxy_stream(is, os) do
      with {:ok, is, data} <- Shadowsocks.Stream.recv(is, 0),
           os <- Shadowsocks.Stream.async_send(os, data) do
        proxy_stream(is, os)
      else
        _e ->
        Shadowsocks.Conn.close(is)
        Shadowsocks.Conn.close(os)
      end
    end

    defp send_bad_request(socket, pid) do
      nginx = random_nginx(pid)
      body = [
        "<html>\n",
        "<head><title>400 Bad Request</title></head>\n",
        "<body bgcolor='white'>\n",
        "<center><h1>400 Bad Request</h1></center>\n",
        "<hr><center>#{nginx}</center>\n",
        "</body>\n",
        "</html>\n"
      ]
      data = [
        "HTTP/1.1 400 Bad Request\r\n",
        "Server: #{nginx}\r\n",
        "Date: #{gmt_date()}\r\n",
        "Content-Type: text/html\r\n",
        "Content-Length: #{153+byte_size(nginx)}\r\n",
        "Connection: close\r\n",
        "\r\n"
        | body
      ]
      Stream.send(socket, data)
    end
    defp send_http_header(socket, pid) do
      data = [
        "HTTP/1.1 101 Switching Protocols\r\n",
        "Server: #{random_nginx(pid)}\r\n",
        "Date: #{gmt_date()}\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Accept: #{:crypto.strong_rand_bytes(16) |> Base.encode64}\r\n",
        "\r\n"
      ]
      Stream.send(socket, data)
    end
    defp gmt_date() do
      date = Date.utc_today
      time = Time.utc_now |> Time.truncate(:second) |> Time.to_iso8601
      ~s|#{@weeks[Date.day_of_week(date)]}, #{String.pad_leading(to_string(date.day), 2, "0")} #{@months[date.month]} #{date.year} #{time} GMT|
    end
    defp random_nginx(pid) do
      seed = :erlang.pid_to_list(pid) |> :lists.sum
      "nginx/1.#{rem(seed, 10)}.#{div(seed, 10) |> rem(10)}"
    end
  end
