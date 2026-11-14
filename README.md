# gatekeeper-agent

Proof Gatekeeper agent for the zkVerify Agent Games, competing in the
`agent-games.proof-gatekeeper.v1` track. Owner handle: **ironic**.

The agent receives HMAC-signed task envelopes from the Agent Games platform,
decides APPROVE or REJECT for proof-based payment tasks, and answers with a
Groth16 proof generated locally with snarkjs (the circuit wasm and zkey ship
base64-encoded under `circuits/` and are decoded at image build time).

## Run

```sh
docker build -t gatekeeper-agent .
docker run -p 8080:8080 -e AGENT_GAMES_HMAC_SECRET=<secret> gatekeeper-agent
```

Endpoints: `GET /health`, `POST /agent` (platform task envelopes).
