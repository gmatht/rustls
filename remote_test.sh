#!/bin/bash

# Deploy script for EasyPeas HTTPS server
# Usage: ./remote_test.sh <target_host>
# Updated for easyp binary with new command line interface
# Uses persistent SSH connection for efficiency

set -e  # Exit on any error

# Set to "--staging" to use Let's Encrypt staging environment, "" for production
#STAGING_FLAG=""
STAGING_FLAG="--staging"
VERBOSE=-v
KEEPALIVE=y

if [ "$1" = quitafter ]
then
	KEEPALIVE=
	shift
fi

if [ -z "$1" ]
then
	SRV=$(cat .remote)
else
	SRV="$1"
fi

echo "DEBUG: Target server is $SRV"
echo "DEBUG: Starting deployment process..."

# SSH connection parameters for persistent connection
# ControlMaster=auto: Automatically use master connection if available
# ControlPath: Path for the control socket
# ControlPersist: Keep connection alive for 60 seconds after last use
SSH_OPTS="-o ControlMaster=auto -o ControlPath=~/.ssh/control-%r@%h:%p -o ControlPersist=60s -o StrictHostKeyChecking=no"
SSH_CMD="ssh $SSH_OPTS root@$SRV"

# Ensure SSH control directory exists
mkdir -p ~/.ssh

# Function to execute commands via persistent SSH
ssh_exec() {
    $SSH_CMD "$@"
}

# Function to cleanup SSH connection
cleanup_ssh() {
    ssh -O exit $SSH_OPTS root@$SRV 2>/dev/null || true
}

# Set up cleanup on script exit
trap cleanup_ssh EXIT

source ~/.cargo/env

# Build if needed
[ -f target/debug/easyp ] || RUSTC_WRAPPER= cargo build --bin easyp
if [ -z "$(find examples/src/ -type f -newer target/debug/easyp 2>/dev/null)" ] || RUSTC_WRAPPER= cargo build --bin easyp
then
	echo "DEBUG: Building completed, starting deployment..."
	
	echo "DEBUG: Killing existing easyp processes on remote server..."
	ssh_exec "pkill easyp;sleep 1;pkill -9 easyp; true" && echo "DEBUG: Process cleanup completed"
	
	echo "DEBUG: Syncing binary to remote server..."
	rsync -avz target/debug/easyp root@$SRV: && echo "DEBUG: Binary sync completed"
	
	echo "DEBUG: Starting server in background..."
	ssh_exec "pkill easyp;sleep 1;pkill -9 easyp; chmod +x easyp; nohup ./easyp --root /var/www/html $VERBOSE $STAGING_FLAG $BOGUS > server.log 2>&1 &"
	echo "DEBUG: Server startup command sent to remote server"
	
	echo "DEBUG: Waiting for server to initialize and certificate generation..."
	
	# Wait up to 30 seconds, but check every 2 seconds if server is ready
	for i in {1..15}; do
		echo "DEBUG: Checking server readiness (attempt $i/15)..."
		if ssh_exec "pgrep easyp > /dev/null && netstat -tlnp | grep -q ':80 ' && grep -q 'Starting EasyPeas' server.log 2>/dev/null"; then
			echo "DEBUG: Server is ready and listening on port 80!"
			break
		fi
		if [ $i -eq 15 ]; then
			echo "DEBUG: WARNING - Server may not be fully ready after 30 seconds"
			echo "DEBUG: Checking server logs for any errors..."
			ssh_exec "tail -10 server.log" || echo "DEBUG: No server log found"
		fi
		sleep 2
	done
	
	echo "DEBUG: Checking if server process is running on remote server..."
	if ssh_exec "pgrep easyp > /dev/null"; then
		echo "DEBUG: Server process is running on remote server"
		echo "DEBUG: Checking server logs for startup completion..."
		ssh_exec "tail -5 server.log"
	else
		echo "DEBUG: ERROR - Server process not found on remote server!"
		echo "DEBUG: Checking server logs..."
		ssh_exec "tail -20 server.log" || echo "DEBUG: No server log found"
		exit 1
	fi
	
	echo "DEBUG: Testing server connectivity..."
	echo "DEBUG: Checking if port 80 is open..."
	if timeout 5 bash -c "echo > /dev/tcp/$SRV/80" 2>/dev/null; then
		echo "DEBUG: Port 80 is open"
	else
		echo "DEBUG: WARNING - Port 80 is not accessible"
	fi
	
	echo "DEBUG: Checking if port 443 is open..."
	if timeout 5 bash -c "echo > /dev/tcp/$SRV/443" 2>/dev/null; then
		echo "DEBUG: Port 443 is open"
	else
		echo "DEBUG: WARNING - Port 443 is not accessible"
	fi
	
	echo "DEBUG: Starting HTTP test with 10 second timeout..."
	echo === HTTP TEST ===
	if timeout 10 curl -v --connect-timeout 5 --max-time 10 "http://$SRV"; then
		echo "DEBUG: HTTP test completed successfully"
		echo "DEBUG: Testing default page (empty document root)..."
		ssh_exec "rm -f /var/www/html/index.html" && echo "DEBUG: Removed index.html to test default page"
		if timeout 15 curl -v --connect-timeout 5 --max-time 15 "http://$SRV" | grep -q "EasyPeas HTTPS Server"; then
			echo "DEBUG: Default page test completed successfully"
		else
			echo "DEBUG: Default page test failed"
		fi
		echo "DEBUG: Testing security headers..."
		if timeout 15 curl -I --connect-timeout 5 --max-time 15 "http://$SRV" | grep -q "X-Content-Type-Options"; then
			echo "DEBUG: Security headers test completed successfully"
		else
			echo "DEBUG: Security headers test failed"
		fi
		echo "DEBUG: Testing path sanitization (directory traversal protection)..."
		if timeout 15 curl -v --connect-timeout 5 --max-time 15 "http://$SRV/../../../etc/passwd" | grep -q "404\|Not Found"; then
			echo "DEBUG: Path sanitization test completed successfully (blocked directory traversal)"
		else
			echo "DEBUG: Path sanitization test failed (potential security issue)"
		fi
	else
		echo "DEBUG: HTTP test failed or timed out"
	fi
	
	sleep 1
	
	echo "DEBUG: Starting HTTPS test with 30 second timeout..."
	echo === HTTPS TEST ===
	if time timeout 160 curl -v --connect-timeout 110 --max-time 130 -k "https://$SRV"; then
		echo "DEBUG: HTTPS test completed successfully"
	else
		echo "DEBUG: HTTPS test failed or timed out"
	fi
	
	sleep 1
	echo === END TESTS ===
	
	if [ -z "$KEEPALIVE" ]
	then
		ssh_exec "pkill easyp; sleep 1; pkill -9 easyp" || echo "DEBUG: Server process cleanup completed"
		echo "DEBUG: Stopping server process on remote server..."
	fi
	
	echo "DEBUG: Test script completed"
fi
