import { useEffect, useState } from "react"
import { RefreshCw, Send } from "lucide-react"
import { evidenceApi } from "../api/client"

interface EvidenceProps {
  onNavigate: (page: string) => void
  onSendToRepeater: (request: unknown) => void
}

export default function Evidence({ onNavigate, onSendToRepeater }: EvidenceProps) {
  const [items, setItems] = useState<any[]>([])
  const [error, setError] = useState("")

  const load = async () => {
    try {
      setItems(await evidenceApi.list())
      setError("")
    } catch {
      setItems([])
      setError("Could not load evidence.")
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const sendToRepeater = (item: any) => {
    onSendToRepeater({ method: item.method || "GET", url: item.url })
    onNavigate("manual-testing")
  }

  return (
    <div className="p-6 max-w-[1200px] mx-auto">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-ink">Evidence</h1>
          <p className="text-sm text-ink-3 mt-1">Sanitized responses captured during authorised DAST scans.</p>
        </div>
        <button onClick={() => void load()} className="p-2 text-ink-3 hover:text-ink" title="Refresh evidence">
          <RefreshCw size={16} />
        </button>
      </div>

      {error && <p className="text-xs text-critical mt-3">{error}</p>}

      <div className="mt-5 bg-card border border-border rounded-lg divide-y divide-border overflow-hidden">
        {items.length ? (
          items.map((item) => (
            <div key={item.id} className="p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-ink truncate">{item.method} {item.url}</p>
                  <p className="text-xs text-ink-3 mt-1">HTTP {item.status_code} - {item.response_length} bytes - {item.content_type || "unknown content"}</p>
                </div>
                <button
                  onClick={() => sendToRepeater(item)}
                  className="inline-flex items-center gap-2 px-3 py-2 bg-elevated border border-border text-ink rounded text-xs"
                >
                  <Send size={14} />
                  Repeater
                </button>
              </div>
              <pre className="mt-3 max-h-32 overflow-auto text-xs text-ink-2 whitespace-pre-wrap">{item.response_excerpt}</pre>
            </div>
          ))
        ) : (
          <p className="p-6 text-sm text-ink-3">No evidence is available yet.</p>
        )}
      </div>
    </div>
  )
}
