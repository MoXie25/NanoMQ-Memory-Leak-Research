
I used `ARG` parameters in the Dockerfile, allowing the use of a single Dockerfile to build images for two different versions by passing different Commit Hashes.

The following is the complete operation procedure, divided into **three stages**: Build Stage, Reproduce v0.24.9, and Reproduce v0.24.6.

### Stage 1: Build Images (Build)

Directory Information:

```
ubuntu1@ubuntu:~/Desktop/mqttDataTest/docker-nanomq$ ls
246exploit_leak.py  249exploit_leak.py  Dockerfile  nanomq.conf

```

Execute the following in the directory containing `Dockerfile` and `nanomq.conf`:

**1. Build v0.24.6 Image**

```
sudo docker build -t nanomq-asan:0.24.6 \
  --build-arg NANOMQ_COMMIT=2557b8de40a5cbcfac76dd028e9e29ccb9158e0a .
```

**2. Build v0.24.9 Image**

```
sudo docker build -t nanomq-asan:0.24.9 \
  --build-arg NANOMQ_COMMIT=2d80f7cff59fab51ec1b7bfe478e3860af91fc39 .
```

### Stage 2: Reproduce v0.24.9

Please follow these steps:

**Step 1: Start v0.24.9 Container**

```
sudo docker run -d \
  --name test-249 \
  -p 1883:1883 \
  nanomq-asan:0.24.9
```

**Step 2: Attach to Foreground (Attach)**

This step is to prepare for pressing `Ctrl+C`.

```
sudo docker attach test-249
```

_(At this point, the terminal will hang waiting for output; this is normal)_

**Step 3: Run Attack Script (In another terminal window)**

Open a new terminal window and run the script for **v0.24.9**:

```
# Note: The filename starts with 249
python3 249exploit_leak.py
```

**Step 4: Trigger Report**

1. Wait for the script to finish running (or observe that the attack is complete).
    
2. Return to the terminal window that is hanging from **Step 2**.
    
3. Press **`Ctrl + C`**.
    
    You will see the ASan red error report for v0.24.9 directly in the terminal. If you can catch this, the entire vulnerability reproduction experiment is complete.
    

**Step 5: Clean Up Environment**

To avoid occupying port 1883, you need to delete the container after testing:

```
sudo docker rm test-249
```

#### 249 Method 2: Start NanoMQ Inside Docker

The following is the complete reproduction process and commands:

#### Step 1: Clean up old container and start a new one

This step will start a container named `test-249-dockerin`, map the ports, and enter the command line directly.

```
# 1. Prevent name conflict, remove existing container with the same name first
sudo docker rm -f test-249-dockerin
```


```
# 2. Start container (modified --name parameter)
sudo docker run -it \
  -p 1883:1883 \
  -p 8081:8081 \
  --name test-249-dockerin \
  --entrypoint /bin/bash \
  nanomq-asan:0.24.9
```

#### Step 2: Start NanoMQ inside the container (Execute inside container)

After executing the above command, you should now be at the `root@xxxx:/usr/local/src/nanomq/build/nanomq#` path inside the container.

Enter the following command to start the Broker:

```
./nanomq start --conf /etc/nanomq.conf
```

**Success Indicator:**

The screen displays logs and finally stops at `NanoMQ Broker is started successfully!`. The cursor hangs without exiting. The host's 1883 port is now ready for connection.

#### Step 3: Run Attack Script

Execute the attack script in the host's terminal window (not inside Docker).

```
python3 249exploit_leak.py
```

#### Step 4: Stop NanoMQ, ASan Error

Next, you can see NanoMQ's log information at the `root@xxxx:/usr/local/src/nanomq/build/nanomq#` path inside the container. Please use `Ctrl+C` to terminate NanoMQ.

You will see the ASan error report.

### Stage 3: Reproduce v0.24.6

Please follow these steps:

**Step 1: Start v0.24.6 Container**

```
sudo docker run -d \
  --name test-246 \
  -p 1883:1883 \
  nanomq-asan:0.24.6
```

**Step 2: Attach to Foreground (Attach)**

This step is to prepare for pressing `Ctrl+C`.

```
sudo docker attach test-246
```

_(At this point, the terminal will hang waiting for output; this is normal)_

**Step 3: Run Attack Script (In another terminal window)**

Open a new terminal window and run the script for **v0.24.6**:

```
python3 246exploit_leak.py
```

**Step 4: Trigger Report**

1. Wait for the script to finish running (or observe that the attack is complete).
    
2. Return to the terminal window that is hanging from **Step 2**.
    
3. Press **`Ctrl + C`**.
    

You will see the ASan red error report for v0.24.6 directly in the terminal. If you can catch this, the entire vulnerability reproduction experiment is complete.

**Step 5: Clean Up Environment**

To avoid occupying port 1883, you need to delete the container after testing:

```
sudo docker rm test-246
```