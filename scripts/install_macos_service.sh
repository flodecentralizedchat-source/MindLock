#!/bin/bash
# install_macos_service.sh — MindLock macOS Native Integration (Phase 7).
# This script installs the "MindLock" Quick Action into Finder's Right-Click menu.

set -e

SERVICE_NAME="MindLock"
SERVICES_DIR="$HOME/Library/Services"
WORKFLOW_PATH="$SERVICES_DIR/$SERVICE_NAME.workflow"
BINARY_DEST="/usr/local/bin/mindlock"

echo "🍏 Installing MindLock macOS Native Service..."

# 1. Install binary to /usr/local/bin for global access
if [ ! -f "./target/release/mindlock" ]; then
    echo "⚠️ Binary not found in ./target/release/mindlock. Building now..."
    cargo build --release
fi

echo "📦 Copying binary to $BINARY_DEST (may require sudo)..."
sudo cp "./target/release/mindlock" "$BINARY_DEST"
sudo chmod +x "$BINARY_DEST"

# 2. Create Workflow directory structure
mkdir -p "$WORKFLOW_PATH/Contents"

# 3. Create Info.plist
cat > "$WORKFLOW_PATH/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>NSServices</key>
	<array>
		<dict>
			<key>NSMessage</key>
			<string>runWorkflowAsService</string>
			<key>NSSentinel</key>
			<string>mindlock_service</string>
			<key>NSMenuItem</key>
			<dict>
				<key>default</key>
				<string>MindLock</string>
			</dict>
			<key>NSRequiredContext</key>
			<dict/>
		</dict>
	</array>
</dict>
</plist>
EOF

# 4. Create the Automator document (running AppleScript)
cat > "$WORKFLOW_PATH/Contents/document.wflow" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>actions</key>
	<array>
		<dict>
			<key>action</key>
			<dict>
				<key>AMAccepts</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Optional</key>
					<true/>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.path</string>
					</array>
				</dict>
				<key>AMActionVersion</key>
				<string>1.1.1</string>
				<key>AMParameterProperties</key>
				<dict>
					<key>source</key>
					<dict/>
				</dict>
				<key>AMProvides</key>
				<dict>
					<key>Container</key>
					<string>List</string>
					<key>Types</key>
					<array>
						<string>com.apple.cocoa.path</string>
					</array>
				</dict>
				<key>ActionBundlePath</key>
				<string>/System/Library/Automator/Run AppleScript.action</string>
				<key>ActionName</key>
				<string>Run AppleScript</string>
				<key>ActionParameters</key>
				<dict>
					<key>source</key>
					<string>on run {input, parameters}
	repeat with theItem in input
		set filePath to POSIX path of theItem
		set fileName to (do shell script "basename " &amp; quoted form of filePath)
		
		if fileName ends with ".mindlock" then
			-- UNLOCK FLOW
			set pass to display dialog "MindLock: Enter password to unlock " &amp; fileName with icon note default answer "" with hidden answer
			set passVal to text returned of pass
			
			try
				set cmd to "$BINARY_DEST unlock " &amp; quoted form of filePath &amp; " --password " &amp; quoted form of passVal
				do shell script cmd
				display notification "File unlocked successfully." with title "MindLock"
			on error errMsg
				display alert "Unlock failed: " &amp; errMsg
			end try
		else
			-- LOCK FLOW
			set pass to display dialog "MindLock: Enter password to secure " &amp; fileName with icon note default answer "" with hidden answer
			set passVal to text returned of pass
			
			try
				set cmd to "$BINARY_DEST lock " &amp; quoted form of filePath &amp; " --shred --password " &amp; quoted form of passVal
				do shell script cmd
				display notification "File secured and shredded." with title "MindLock"
			on error errMsg
				display alert "Lock failed: " &amp; errMsg
			end try
		end if
	end repeat
	return input
end run</string>
				</dict>
				<key>BundleIdentifier</key>
				<string>com.apple.Automator.RunScript</string>
				<key>CFBundleVersion</key>
				<string>1.1.1</string>
				<key>CanShowSelectedItemsWhenRun</key>
				<false/>
				<key>CanShowWhenRun</key>
				<true/>
				<key>Category</key>
				<array>
					<string>AMCategoryUtilities</string>
				</array>
				<key>Class Name</key>
				<string>RunScriptAction</string>
				<key>InputUUID</key>
				<string>INPUT_ID</string>
				<key>Keywords</key>
				<array>
					<string>Run</string>
					<string>AppleScript</string>
				</array>
				<key>OutputUUID</key>
				<string>OUTPUT_ID</string>
				<key>UUID</key>
				<string>UUID_ID</string>
				<key>UnlocalizedApplications</key>
				<array>
					<string>Automator</string>
				</array>
				<key>arguments</key>
				<dict>
					<key>0</key>
					<dict>
						<key>default value</key>
						<string>on run {input, parameters}
	
	return input
end run</string>
						<key>name</key>
						<string>source</string>
						<key>required</key>
						<string>0</string>
						<key>type</key>
						<string>0</string>
					</dict>
				</dict>
				<key>isViewVisible</key>
				<true/>
				<key>location</key>
				<string>309.000000:316.000000</string>
				<key>nibPath</key>
				<string>/System/Library/Automator/Run AppleScript.action/Contents/Resources/Base.lproj/main.nib</string>
			</dict>
		</dict>
	</array>
	<key>connectors</key>
	<dict/>
	<key>workflowMetaData</key>
	<dict>
		<key>applicationBundleIDsByPath</key>
		<dict/>
		<key>applicationPaths</key>
		<array/>
		<key>inputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>outputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>presentationMode</key>
		<integer>15</integer>
		<key>processesInput</key>
		<integer>0</integer>
		<key>serviceInputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>serviceOutputTypeIdentifier</key>
		<string>com.apple.Automator.nothing</string>
		<key>servicePresentationMode</key>
		<integer>15</integer>
		<key>specifiedInputTypeIdentifier</key>
		<string>com.apple.Automator.fileSystemObject</string>
		<key>workflowTypeIdentifier</key>
		<string>com.apple.Automator.servicesMenu</string>
	</dict>
</dict>
</plist>
EOF

echo "✅ MindLock Quick Action installed!"
echo "👉 You can now right-click any file in Finder and select 'Quick Actions > MindLock'."
echo "🚀 If you don't see it, go to System Settings > Keyboard > Keyboard Shortcuts > Services and enable it."
