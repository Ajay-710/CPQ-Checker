import { useState, useRef, useEffect } from 'react'
import './App.css'

const API_BASE = import.meta.env.VITE_API_URL || ''

function App() {
  const [results, setResults] = useState([])
  const [isScanning, setIsScanning] = useState(false)
  const [domainsInput, setDomainsInput] = useState('')
  const [deepScan, setDeepScan] = useState(false)
  const [dragActive, setDragActive] = useState(false)
  const [progress, setProgress] = useState(null)
  const [scanError, setScanError] = useState('')
  
  const eventSourceRef = useRef(null)

  const stopScan = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }
    setIsScanning(false)
  }

  useEffect(() => {
    return () => {
      stopScan()
    }
  }, [])

  const handleStream = (url, options = {}) => {
    setResults([])
    setProgress(null)
    setScanError('')
    setIsScanning(true)
    
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
    }
    
    fetch(url, options)
      .then(async response => {
        if (!response.ok) {
          throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
        }
        const reader = response.body.getReader()
        const decoder = new TextDecoder('utf-8')
        let buffer = ''
        let receivedDone = false
        
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          
          buffer += decoder.decode(value, { stream: true })
          const lines = buffer.split('\n')
          buffer = lines.pop()
          
          let eventType = 'message'
          let eventData = ''
          
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i]
            if (line.startsWith('event: ')) {
              eventType = line.substring(7).trim()
            } else if (line.startsWith('data: ')) {
              eventData = line.substring(6).trim()
              
              if (eventType === 'result') {
                try {
                  const resultObj = JSON.parse(eventData)
                  setResults(prev => [resultObj, ...prev])
                } catch (e) {
                  console.error('Error parsing result data:', e)
                }
              } else if (eventType === 'progress') {
                try {
                  setProgress(JSON.parse(eventData))
                } catch (e) {
                  console.error('Error parsing progress data:', e)
                }
              } else if (eventType === 'done') {
                receivedDone = true
                setIsScanning(false)
              }
            }
          }
        }

        // A proxy/deployment can close an SSE connection before the backend
        // sends its done event. Never leave the controls permanently locked.
        if (!receivedDone) {
          setScanError('Scan connection closed before a result was returned. Please retry; if it repeats, check the service logs.')
          setIsScanning(false)
        }
      })
      .catch(err => {
        console.error('Stream error:', err)
        setScanError(`Scan request failed: ${err.message}`)
        setIsScanning(false)
      })
  }

  const handleManualSubmit = (e) => {
    e.preventDefault()
    if (!domainsInput.trim()) return
    
    handleStream(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domains: domainsInput, deep_scan: deepScan })
    })
  }

  const handleFileUpload = (e) => {
    const file = e.target.files && e.target.files[0]
    if (!file) return
    uploadFile(file)
  }

  const uploadFile = (file) => {
    const formData = new FormData()
    formData.append('file', file)
    formData.append('deep_scan', deepScan)
    
    handleStream(`${API_BASE}/api/upload`, {
      method: 'POST',
      body: formData
    })
  }

  const handleDrag = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true)
    } else if (e.type === "dragleave") {
      setDragActive(false)
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      uploadFile(e.dataTransfer.files[0])
    }
  }

  const getConfidenceBadge = (confidence) => {
    const map = {
      'CONFIRMED': 'confirmed',
      'LIKELY': 'likely',
      'POSSIBLE': 'possible',
      'NOT_DETECTED': 'none',
      'SCAN_FAILED': 'error'
    }
    const c = map[confidence] || 'error'
    return <span className={`badge ${c}`}>{confidence}</span>
  }

  return (
    <>
      <header className="hero">
        <div style={{marginBottom: '0.5rem'}}>
          <span className="retro-tag">v2.0-zaggonaut</span>
          <span className="retro-tag">retro-engine</span>
        </div>
        <h1>CPQ Detector</h1>
      </header>
      
      <div className="controls-grid">
        <div className="glass-card">
          <h2>Manual Scan</h2>
          <form onSubmit={handleManualSubmit}>
            <p style={{fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1rem'}}>
              Enter single or comma-separated domain targets:
            </p>
            <div className="input-group">
              <input 
                type="text" 
                placeholder="salesforce.com, oracle.com" 
                value={domainsInput}
                onChange={e => setDomainsInput(e.target.value)}
                disabled={isScanning}
              />
              <button className="btn" type="submit" disabled={isScanning || !domainsInput.trim()}>
                {isScanning ? <span className="loader"></span> : '[ SCAN ]'}
              </button>
            </div>
            <label className="checkbox-container">
              <input type="checkbox" checked={deepScan} onChange={e => setDeepScan(e.target.checked)} disabled={isScanning} />
              Enable Deep Crawl (crawl linked pages for fingerprints)
            </label>
          </form>
        </div>

        <div className="glass-card">
          <h2>Bulk CSV Upload</h2>
          <p style={{fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1rem'}}>
            Select a CSV list with website/domain columns:
          </p>
          <label 
            className={`file-upload ${dragActive ? "drag-active" : ""}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#171717" strokeWidth="2.5" strokeLinecap="square">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="17 8 12 3 7 8"></polyline>
              <line x1="12" y1="3" x2="12" y2="15"></line>
            </svg>
            <p style={{fontWeight: 600, color: '#171717'}}>Drag & Drop CSV file here or click to browse</p>
            <input type="file" accept=".csv" onChange={handleFileUpload} disabled={isScanning} />
          </label>
        </div>
      </div>

      {(results.length > 0 || isScanning) && (
        <div className="results-container glass-card">
          <div className="results-header">
            <h2>Scan Output [{results.length}]</h2>
            {isScanning && (
              <div style={{display: 'flex', alignItems: 'center', gap: '1rem'}}>
                <span style={{fontSize: '0.9rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem'}}>
                  <span className="loader"></span> {progress ? `Scanning ${progress.completed}/${progress.total} target${progress.total === 1 ? '' : 's'}...` : 'Starting scan...'}
                </span>
                <button className="btn" style={{padding: '0.4rem 0.8rem', fontSize: '0.8rem'}} onClick={stopScan}>[ STOP ]</button>
              </div>
            )}
          </div>
          {scanError && <p style={{color: 'var(--accent-red)', fontWeight: 600, margin: '0 0 1rem'}}>{scanError}</p>}
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Target Domain</th>
                  <th>Status</th>
                  <th>Vendor Detected</th>
                  <th>Confidence</th>
                  <th>Evidence Snippet</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => (
                  <tr key={i}>
                    <td style={{fontWeight: 600}}>
                      {r.final_url ? (
                        <a href={r.final_url} target="_blank" rel="noreferrer" style={{color: '#171717', textDecoration: 'underline', textUnderlineOffset: '4px'}}>
                          {r.domain}
                        </a>
                      ) : r.domain}
                    </td>
                    <td>
                      {r.error ? (
                        <span title={r.error} style={{color: 'var(--accent-red)', fontWeight: 700, cursor: 'help'}}>[ ERR ]</span>
                      ) : (
                        `HTTP ${r.http_status || '200'}`
                      )}
                    </td>
                    <td style={{fontWeight: 700}}>{r.cpq_vendor || '-'}</td>
                    <td>{getConfidenceBadge(r.confidence)}</td>
                    <td className="evidence-cell" title={r.error || r.evidence}>{r.error || r.evidence || '-'}</td>
                  </tr>
                ))}
                {results.length === 0 && (
                  <tr>
                    <td colSpan="5" style={{textAlign: 'center', padding: '2rem', color: 'var(--text-muted)'}}>
                      No domains scanned yet. Submit a domain above to initialize scan stream.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  )
}

export default App
