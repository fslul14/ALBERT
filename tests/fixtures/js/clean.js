// Ordinary code with false-positive bait: none of this should produce a finding.
const docs = "https://developer.mozilla.org/en-US/docs/Web";
const blog = "https://dev.to/someone/post";
const cdn = "https://www.test.com/lib.js";
let isDebug = false;
const placeholder = { apiKey: "${API_KEY}", token: "<your-token>" };
function tokenize(s) { return s.split(" "); }
