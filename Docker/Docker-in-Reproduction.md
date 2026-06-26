## Environment

All related files are located in the `docker-nanomq` directory.

Test environment:

```text
OS: Ubuntu 20.04
Docker: Docker version 26.1.3, build 26.1.3-0ubuntu1~20.04.1
````

The directory contains the following files:

```text
Dockerfile
nanomq.conf
249exploit_leak.py
```

## Reproduction Steps

### 1. Build the Docker Image

Run the following command in the directory containing `Dockerfile`, `nanomq.conf`, and `249exploit_leak.py`:

```bash
sudo docker build --network=host -t nanomq-249-dockerin .
```

Expected output:

```text
Successfully tagged nanomq-249-dockerin:latest
```

### 2. Start the Container

Run the following command on the host machine:

```bash
sudo docker run -it --name nanomq-249-dockerin nanomq-249-dockerin
```

After this command is executed, the current terminal will enter the Docker container.

### 3. Start NanoMQ Inside the Container

Run the following command inside the container:

```bash
./nanomq start --conf /etc/nanomq.conf
```

Expected output:

```text
NanoMQ Broker is started successfully!
```

Keep this terminal open.

### 4. Run the PoC in a New Host Terminal

Open a new terminal on the host machine and enter the same running container:

```bash
sudo docker exec -it nanomq-249-dockerin /bin/bash
```

Then run the PoC:

```bash
python3 /tmp/249exploit_leak.py
```

Expected output: the PoC completes multiple rounds of MQTT interactions, for example:

```text
[*] Round 1/5
[*] Target: 127.0.0.1:1883
[C1] <<< RECEIVED DATA: 200200009003000101
[C2] Publish sent. Closing C2.
[*] Interaction finished.
```

### 5. Trigger LeakSanitizer Output

Return to the first container terminal where NanoMQ is running, then press:

```text
Ctrl + C
```

Expected output:

```text
ERROR: LeakSanitizer: detected memory leaks
SUMMARY: AddressSanitizer: xxx byte(s) leaked in xxx allocation(s).
```

## Notes

1. The PoC is executed inside the same Docker container to avoid host-to-container port mapping issues. The PoC still connects to NanoMQ Broker through TCP at `127.0.0.1:1883`, simulating normal MQTT client-server interaction.

2. The complete process is shown in the attached logs.

3. The related operation process can also be referenced in the video.