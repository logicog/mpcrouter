echo -n "SESSION_SECRET=" >> mpcrouter
echo `ruby -e "require 'securerandom'; puts SecureRandom.hex(64)"`>> mpcrouter
