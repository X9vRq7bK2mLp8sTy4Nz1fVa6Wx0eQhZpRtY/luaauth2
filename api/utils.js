const allowedUAs = ['synapse', 'krnl', 'fluxus', 'script-ware', 'scriptware', 'sentinel', 'executor', 'roblox', 'exploit', 'electron'];

function isAllowedUA(userAgent) {
  if (!userAgent) return false;
  userAgent = userAgent.toLowerCase();
  return allowedUAs.some(sub => userAgent.includes(sub));
}

module.exports = { isAllowedUA };
