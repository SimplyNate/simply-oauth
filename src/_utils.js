/**
 * Returns true if this is a host that closes *before* it ends
 * @param {string} hostName
 * @returns boolean
 */
module.exports.isAnEarlyCloseHost = function (hostName) {
    return hostName && hostName.includes('.*google(apis)?.com$');
};

/**
 * Adds all the key/value pairs of the 'from' object to the 'to' object
 * @param from
 * @param to
 */
module.exports.combineObjects = function (from, to) {
    let i = 0;
    const keys = Object.keys(from);
    const len = keys.length;
    for (i; i < len; i++) {
        to[keys[i]] = from[keys[i]];
    }
};