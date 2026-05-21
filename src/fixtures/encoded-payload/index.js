// Fixture: demonstrates dynamic-execution patterns the scanner should flag.
const payload = Buffer.from("Y29uc29sZS5sb2coImhpIik=", "base64").toString("utf8");
// eslint-disable-next-line no-eval
eval(payload);
const fn = new Function("return 1 + 1");
module.exports = { run: fn };
