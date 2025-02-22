# set npm environment

# Download and install nvm:
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash

# in lieu of restarting the shell
\. "$HOME/.nvm/nvm.sh"

# Download and install Node.js:
nvm install 23

# Verify the Node.js version:
node -v # Should print "v23.8.0".
nvm current # Should print "v23.8.0".

# Verify npm version:
npm -v # Should print "10.9.2".

cd Mailspring
# export npm_config_arch=x64 # If you are on an M1 / Apple Silicon Mac

npm config set proxy http://127.0.0.1:7890
npm config set https-proxy http://127.0.0.1:7890
npm install

echo 'export NVM_DIR="$HOME/.nvm"\n[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm' | ~/.bashrc
# npm start