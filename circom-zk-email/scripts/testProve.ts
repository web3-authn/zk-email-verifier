import * as fs from "fs";
import * as path from "path";

async function main() {
  const emlPath = path.join(__dirname, "../emls/gmail_reset_full.eml");
  const rawEmail = fs.readFileSync(emlPath, "utf-8");

  console.log("Sending email to /prove-email...");

  const response = await fetch("http://localhost:5588/prove-email", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rawEmail }),
  });

  if (!response.ok) {
    const error = await response.json();
    console.error("Error:", error);
    process.exit(1);
  }

  const result = await response.json();
  console.log("Success!");
  console.log("Proof:", JSON.stringify(result.proof, null, 2));
  console.log("Public Signals:", JSON.stringify(result.publicSignals, null, 2));
}

main().catch(console.error);
