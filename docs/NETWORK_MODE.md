# Containerised network mode

The normal way to run ics-sim is in-process: every simulated host's Modbus request goes through
`Simulation.request`, and the source addresses are labels. That is fast and deterministic, and the
matrix uses it. Network mode is an optional second deployment where the same requests cross real
Docker networks and a real firewall process, so you can check that the in-process policy model
behaves like a network boundary.

```
 enterprise 192.168.10.0/24 (internal)      dmz 10.10.2.0/24 (internal)          control 10.10.1.0/24 (internal)
 +-------------------------+                +---------------------------+         +--------------------------+
 | labclient 192.168.10.37 |                | hmi    10.10.2.10 (polls) |         | plc 10.10.1.10           |
 | (CORP-WS-37, read_plant |                | ews    10.10.2.20         |         | icssim serve, Modbus 5020|
 |  and scenario replay)   |                | rogue  10.10.2.66         |         | HUD 8104                 |
 +-----------+-------------+                +-------------+-------------+         +------------+-------------+
             |                                            |                                    |
             +-------- 192.168.10.254 --+  +-- 10.10.2.254 +                      10.10.1.254 --+
                                        |  |                                                   |
                                   +----+--+---------------------------------------------------+-+
                                   | fw  (python -m icssim.fwgate)                                |
                                   | segmentation -> DPI -> forward with PROXY v1 header, or drop |
                                   | one JSON line per decision on stdout                         |
                                   +----------------------------+---------------------------------+
                                                                | 10.10.99.254, edge bridge (no NAT)
                                                                v
                                                   host 127.0.0.1:8124 -> PLC HUD (TCP relay only)
```

## Design decisions

- **Three internal networks.** `enterprise`, `dmz` and `control` are Docker networks with
  `internal: true`, so they have no route out and no route to each other. The firewall container is
  the only one attached to more than one of them, which makes it the only path from a client to the PLC.
- **The HMI tier.** The task layout puts the HMI in the DMZ. The simulator's Purdue table has a
  separate DMZ (172.16.0.0/24) and puts HMI-01 at 10.10.2.10 in the supervisory zone (L2). To keep
  the zone policy unchanged, the middle network uses the HMI's subnet 10.10.2.0/24. It is the
  DMZ between Enterprise IT and the control network in this layout, and the policy still sees its
  hosts as zone `supervisory`. A real deployment would split the DMZ and L2. That would mean a fourth
  network and the same gateway code.
- **Real source addresses.** Every client container has the address its simulated host has
  (HMI-01, EWS-01, the rogue laptop from the replay and logic scenarios, CORP-WS-37). The gateway
  decides on the address it sees on the socket, using the unchanged zone table, so a scenario's
  attacker is blocked or allowed because of where its container actually sits.
- **Application-layer gateway, not a packet filter.** All containers run with `cap_drop: [ALL]`, so
  nothing can use NET_ADMIN, nftables or raw sockets. The gateway is therefore a Modbus-aware proxy.
  It reads each MBAP frame, decides, then forwards the request or drops it. This is how most
  commercial Modbus firewalls work too. A dropped request gets no reply, the same as in the simulator.
- **Separate rule engine, same policy data.** `icssim/fwgate.py` does not import the simulator. It
  loads `policy.json`, which `python -m icssim export-policy` writes from `icssim/network.py` at image
  build time. The zones, segmentation table, DPI allowlist, function codes, write targets and rate
  limit are defined once, but the code that evaluates them is separate. `tests/test_fwgate.py` compares
  the two implementations over more than 2 000 request, source and unit combinations in each of the
  three firewall configurations, and over irregular bursts for the rate limiter.
- **Source identity at the PLC.** The gateway opens one upstream connection per client and starts
  it with a PROXY protocol v1 line (`PROXY TCP4 <client> <gateway> <ports>`). The PLC reads that line
  only from 10.10.1.254 (`ICSSIM_TRUSTED_PROXIES`). A client cannot claim an address, because no one
  else's header is parsed and clients cannot reach the control network anyway. The PLC's Modbus log
  therefore shows the real client address with transport `tcp`. Inside the PLC the simulator's own
  segmentation and DPI stay off, because the gateway is now the boundary.
- **Hardening.** Every container runs as uid 10001 with a read-only root filesystem, `cap_drop: [ALL]`,
  `no-new-privileges`, a small `/tmp` tmpfs, a pids limit, a memory limit and a CPU quota of 0.25 to 0.5.
  The PLC writes reports to a tmpfs at `/app/data`. The only host port is `127.0.0.1:8124`, the PLC HUD.
  The gateway relays it from the `edge` bridge, which has masquerading switched off, so even the gateway
  has no internet path. The relay listens only on the edge address, so IT and DMZ clients cannot reach
  the HUD's control API.

## Running it

```
./netmode.sh verify     # build, start, replay all scenarios, compare, write data/netmode/, stop
./netmode.sh up         # build and start; PLC HUD on http://127.0.0.1:8124/
./netmode.sh down
python -m icssim netmode plan oldsmar     # the requests a scenario sends and the simulator's decisions
```

`netmode.sh` runs the build and the verification under the lab's CPU lock at low priority.

## What `verify` does

1. Builds the image (python:3.12-slim with fastapi and uvicorn) and starts six containers.
2. Waits for the PLC HUD through the gateway's relay on 127.0.0.1:8124 and sets the plant to 1x speed.
3. Runs isolation probes from inside the containers: direct TCP to the PLC from IT and from the DMZ,
   IT to the HMI, the HMI to the internet, and IT to its own gateway address.
4. Runs `tools/read_plant.py` from the lab client in IT and from the HMI container, both through the gateway.
5. For each of the eight scenarios, runs it in-process with segmentation and DPI on and records every
   request with the simulator's decision (`Simulation.recorder`). The replay set is every attack request,
   200 requests of the DoS flood (the simulator sends 2.4 million) and two HMI polls after the attack
   starts. Each request is sent from the container that owns its source address.
6. Sends five policy probes that the scenarios do not cover (an HMI alarm-limit write, FC 90 from the
   HMI, an HMI read of the SIS unit, an allowed setpoint write, an EWS server ID request) and an
   80-request burst from the HMI for the rate limiter.
7. Checks three things:
   - each replayed request appears in the gateway log under the container's own address and port,
     with the same decision, layer and reason as the in-process simulator;
   - every gateway log line, including the HMI container's own polling, gives the same decision when
     replayed through `network.Firewall.decide` in log order at the gateway's logged times;
   - the PLC's Modbus log holds the allowed attack and probe requests under their original addresses
     and nothing from the sources that were always blocked.
8. Writes `data/netmode/evidence.md`, `evidence.json` and `fw.log`, then runs `docker compose down`.

## Verification run (2026-11-14 19:04)

`./netmode.sh verify` passed: 37 s for start, checks and stop, with the image already built. The
first build took several minutes because PyPI was slow from this network. Full output goes to
`data/netmode/evidence.md`. Summary:

- **Isolation.** Direct TCP from the lab client (IT) to the PLC, from the HMI (DMZ) to the PLC, and
  from IT to the HMI all fail with "Network is unreachable". The HMI cannot reach the internet. The
  lab client can open a connection to its own gateway address, and nothing else.
- **Lab client.** `tools/read_plant.py` from the IT container gets no answer at all (segmentation).
  From the HMI container it reads every PLC value, setpoint and coil. Its FC 17 server ID request is
  dropped (not in the HMI's function codes) and so is the SIS read on unit 2 (segmentation).
- **Scenario traffic.** 90 replayed items: 85 from the eight scenarios, where the DoS flood sample is
  one item of 200 requests, plus the five policy probes. Each was logged by the gateway under its
  container's own address and port, with the same decision, layer and reason as the in-process
  simulator (90 of 90). The client saw a reply exactly
  when the gateway allowed the request. Blocked: setpoint_change (3, zone enterprise), the DoS flood
  sample (200 requests in one burst, zone enterprise), logic_tamper (3, rogue laptop not in the
  allowlist), sis_bypass (2, zone supervisory may not reach the SIS). Allowed, as in the matrix's
  firewall and segmentation columns: the Oldsmar write, the replay scenario's HMI-session writes, the
  insider's writes and the sis_bypass follow-up writes. The probes were blocked by the write-target
  rule, the function-code rule and segmentation, and two allowed requests got through.
- **Whole log re-checked.** All 444 gateway decisions, including the HMI container's own polling
  and an 80-request burst, gave the identical decision, layer and reason when replayed through
  `network.Firewall.decide` at the gateway's logged times: 217 allowed, 227 blocked, 12 of them by the
  20 req/s rate limit (69 of the 80 burst reads were answered).
- **At the PLC.** The PLC's Modbus log holds 217 TCP transactions, attributed through the PROXY header
  to 10.10.2.10 (211) and 10.10.2.20 (6). That matches the 217 allowed decisions. All 14 allowed attack
  and probe requests are there. Nothing from 192.168.10.37 or 10.10.2.66, the two sources that were
  always blocked, reached the PLC.

## Limits

- The replay keeps the order of requests but not their simulated timing. The flood is sampled, not
  replayed in full. Rate-limit decisions are compared against the gateway's own wall-clock times,
  not against the simulated times of the in-process run.
- The FDI scenario acts at field level and the replay scenario's adversary in the middle sits inside
  the simulator, so for those two only the HMI-session traffic crosses the network.
- The PLC container still runs the in-process HMI model and operator, so its HUD keeps working.
  The HMI container is a second, real client that polls through the gateway.
- One verification run is a functional check, not a load or timing test.
