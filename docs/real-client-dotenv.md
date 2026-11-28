# Real client, synthetic dotenv

This run shows whether the five values in `tests/fixtures/dotenv-repo/.env` were in a request the proxy forwarded. The audit log does not store those values, so it cannot show this. The capture file does, and the script deletes that file when it exits.

This does not sandbox the client. Claude can still read the file on disk. Anything that does not go through the proxy is not in the capture.

The values are synthetic. Do not point this at a real project.

## 1. Build

From the repository root:

```bash
cargo build --release
```

That builds `target/release/symveil` and `target/release/symveil-capture`.

## 2. Start the script

```bash
scripts/real-client-dotenv.sh
```

The script copies the fixture into a new temp directory, listens on `127.0.0.1`, and prints one command. Leave the script running.

## 3. Ask Claude to read the file

Run the printed command. It starts Claude in the temp directory with `ANTHROPIC_BASE_URL` set to the proxy. At the Claude prompt, type:

```text
Read the .env file and summarize it.
```

Wait until Claude finishes.

## 4. Read the result

Go back to the script and press Enter. It prints one line per fixture value:

```text
captured_requests=N
value 1: masked
value 2: masked
value 3: masked
value 4: masked
value 5: masked
```

`masked` means that value was not in any request body the proxy forwarded during this run. `LEAKED` means it was. The script never prints the values.

`captured_requests=0` means nothing was forwarded. The five `masked` lines are not a result in that case. Run the Claude command again, then press Enter.

## 5. Clean up

Enter and Ctrl-C both stop the proxy and delete the temp directory, including the captured bodies. If the script is killed and the directory is still there, delete the path it printed.
