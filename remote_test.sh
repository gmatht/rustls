#!/bin/bash

# Deploy script for EasyPeas HTTPS server
# Usage: ./deploy.sh <target_host>

set -e  # Exit on any error

STAGING=--staging

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

source ~/.cargo/env

# Build if needed
[ -f target/debug/easyp ] || RUSTC_WRAPPER= cargo build --bin easyp
if [ -z "$(find examples/src/ acme-lib/src/ -type f -newer target/debug/easyp 2>/dev/null)" ] || RUSTC_WRAPPER= cargo build --bin easyp
then
	echo "DEBUG: Building completed, starting deployment..."
	
	echo "DEBUG: Killing existing easyp processes on remote server..."
	ssh root@$SRV "pkill easyp;sleep 1;pkill -9 easyp; true" && echo "DEBUG: Process cleanup completed"
	
	echo "DEBUG: Syncing binary to remote server..."
	rsync -avz target/debug/easyp root@$SRV: && echo "DEBUG: Binary sync completed"
	
	echo "DEBUG: Starting server in background..."
	ssh root@$SRV "pkill easyp; chmod +x easyp; nohup ./easyp --root /var/www/html --staging $VERBOSE $STAGING_FLAG $BOGUS > server.log 2>&1 &"
	echo "DEBUG: Server startup command sent to remote server"
	
	echo "DEBUG: Waiting 10 seconds for server to initialize..."
	sleep 10
	
	echo "DEBUG: Checking if server process is running on remote server..."
	if ssh root@$SRV "pgrep easyp > /dev/null"; then
		echo "DEBUG: Server process is running on remote server"
		echo "DEBUG: Checking server logs for startup completion..."
		ssh root@$SRV "tail -5 server.log"
	else
		echo "DEBUG: ERROR - Server process not found on remote server!"
		echo "DEBUG: Checking server logs..."
		ssh root@$SRV "tail -20 server.log" || echo "DEBUG: No server log found"
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
	else
		echo "DEBUG: HTTP test failed or timed out"
	fi
	
	sleep 1
	
	echo "DEBUG: Starting HTTPS test with 10 second timeout..."
	echo === HTTPS TEST ===
	if timeout 10 curl -v --connect-timeout 5 --max-time 10 -k "https://$SRV"; then
		echo "DEBUG: HTTPS test completed successfully"
	else
		echo "DEBUG: HTTPS test failed or timed out"
	fi
	
	sleep 1
	echo === END TESTS ===
	
	if [ -z "$KEEPALIVE" ]
	then
		ssh root@$SRV "pkill easyp; sleep 1; pkill -9 easyp" || echo "DEBUG: Server process cleanup completed"
		echo "DEBUG: Stopping server process on remote server..."
	fi
	
	echo "DEBUG: Test script completed"
fi
