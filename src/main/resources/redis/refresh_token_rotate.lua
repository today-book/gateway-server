-- refresh_token_rotate.lua
-- KEYS[1] = oldRefreshToken
-- KEYS[2] = newRefreshToken
-- ARGV[1] = ttlSeconds

local userId = redis.call("GET", KEYS[1])
if not userId then
  return nil
end

redis.call("DEL", KEYS[1])
redis.call("SET", KEYS[2], userId, "EX", ARGV[1])

return userId