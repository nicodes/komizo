// Expo's preset, and nothing else -- the same call the reference app made in
// its babel.config.js: no styling runtime, no build step for markup that is
// written out directly.
module.exports = function (api) {
  api.cache(true);
  return { presets: ['babel-preset-expo'] };
};
