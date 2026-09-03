import { useState } from "react"
import { Wand2 } from "lucide-react"
import { manualApi } from "../api/client"

const MODES = [
  ["url-decode", "URL decode"],
  ["url-encode", "URL encode"],
  ["base64-decode", "Base64 decode"],
  ["base64-encode", "Base64 encode"],
  ["json-pretty", "Pretty JSON"],
  ["hash-sha256", "SHA-256"],
]

export default function Decoder() {
  const [mode, setMode] = useState("url-decode")
  const [input, setInput] = useState("")
  const [output, setOutput] = useState("")
  const [error, setError] = useState("")

  const run = async () => {
    setError("")
    try {
      const result = await manualApi.decode(mode, input)
      setOutput(result.output)
    } catch (reason: any) {
      setError(reason.message || "Decode failed.")
    }
  }

  return (
    <div className="p-6 max-w-[1200px] mx-auto space-y-5">
      <div>
        <h1 className="text-lg font-semibold text-ink">Decoder</h1>
        <p className="text-sm text-ink-3 mt-1">Encode, decode, pretty-print, and hash payloads while testing.</p>
      </div>
      <div className="bg-card border border-border rounded-lg p-4 flex flex-wrap gap-3 items-center">
        <select value={mode} onChange={(event) => setMode(event.target.value)} className="bg-canvas border border-border rounded px-3 py-2 text-sm text-ink">
          {MODES.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
        </select>
        <button onClick={() => void run()} className="inline-flex items-center gap-2 px-4 py-2 bg-accent text-white rounded text-sm">
          <Wand2 size={15} /> Transform
        </button>
        {error && <p className="text-xs text-critical">{error}</p>}
      </div>
      <div className="grid lg:grid-cols-2 gap-5">
        <TextPanel title="Input" value={input} setValue={setInput} />
        <TextPanel title="Output" value={output} setValue={setOutput} />
      </div>
    </div>
  )
}

function TextPanel({ title, value, setValue }: { title: string; value: string; setValue: (value: string) => void }) {
  return (
    <section className="bg-card border border-border rounded-lg overflow-hidden">
      <header className="p-3 border-b border-border text-sm font-semibold text-ink">{title}</header>
      <textarea value={value} onChange={(event) => setValue(event.target.value)} spellCheck={false} className="w-full h-[520px] bg-card p-4 text-xs font-mono text-ink-2 resize-none" />
    </section>
  )
}
