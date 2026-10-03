# Aegis VirtualBox test

This quick setup runs the control plane on one Ubuntu VM and an agent on each
of one Ubuntu VM and one Windows 11 VM. Each VM gets its own mTLS identity.
These scripts and sample credentials are for an isolated test network, not
production.

## One-time VirtualBox setup

1. Give all three VMs bridged networking and reserve a stable IPv4 address for
   the control-plane VM.
2. Create one VirtualBox shared folder named `aegis`, enable Auto-mount, and
   make it available to all three VMs. Install VirtualBox Guest Additions.
   Ubuntu usually mounts it at `/media/sf_aegis`; Windows can access it at
   `\\VBOXSVR\aegis`.
3. Clone this repository on each VM. The Ubuntu control-plane setup installs
   Docker Engine and Compose; the agent setup scripts install/run the agents.
   Install Git first if the VM does not already have it.

On each Ubuntu VM:

```sh
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/lschwe04/aegis-platform.git
cd aegis-platform
```

On Windows, install Git for Windows if needed, then clone the same repository
and open PowerShell in the cloned folder:

```powershell
git clone https://github.com/lschwe04/aegis-platform.git
Set-Location aegis-platform
```

## Control-plane Ubuntu VM

Find the VM's bridged address with `hostname -I`. From the cloned repository,
run this once (replace the example IP and shared-folder path):

```sh
sudo bash scripts/setup-control-plane.sh 192.168.1.50 /media/sf_aegis
```

The script installs Docker if needed, creates the HTTPS/mTLS certificates,
builds both agents, puts their separate bundles in the shared folder, creates
`.env`, starts Postgres and the control plane, and waits for both to become
healthy. It prints the dashboard password at the end. Keep the CA private key
under `certs/ca` on this VM; it is not copied to the shared folder.
Because this is one shared folder, both agent VMs can access both test client
keys. Use it only on an isolated lab network.

## Ubuntu agent VM

Clone the repository, make sure the control-plane setup above has finished,
then run:

```sh
sudo bash scripts/setup-ubuntu-agent.sh /media/sf_aegis/aegis-vbox
```

The script installs the Ubuntu agent, registers it, and enables a systemd
service that runs after reboot. View its live logs with:

```sh
sudo journalctl -u aegis-agent -f
```

## Windows 11 agent VM

Clone the repository and open PowerShell **as Administrator**. The shared
folder is normally `\\VBOXSVR\aegis`:

```powershell
.\scripts\setup-windows-agent.ps1 -BundlePath "\\VBOXSVR\aegis\aegis-vbox"
```

The script installs and registers the agent, imports the test certificates,
and creates a startup task that keeps sending results after reboot. Its log is
`C:\ProgramData\Aegis\agent.log`. The Windows client certificate is also
installed for the current user so the browser can access the dashboard.

## View results and reset

Open `https://192.168.1.50:8000/api/v1/dashboard/ui` from Windows, replace the
example IP, select the Windows client certificate if asked, and sign in as
`admin` using the password printed by the control-plane script (the default
test password is `AegisLab2026!`). Both agents should report `[PUSH OK]` in
their logs.

On the control-plane VM:

```sh
docker compose ps
docker compose logs --tail 50 control-plane
```

Stop the test and preserve its database with `docker compose down`. To erase
the test database and start over, use `docker compose down -v`.

## Development

Run Go tests from `agent-go` with `go test ./...`; run control-plane tests from
`control-plane` with `pytest`. `docker-compose.prod.yml` and the RMM deployment
scripts are separate deployment examples, not part of this VirtualBox test.
