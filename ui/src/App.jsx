import { useState, useRef, useEffect } from 'react'
import './App.css'

function App() {
  const [results, setResults] = useState([])
  const [isScanning, setIsScanning] = useState(false)
  const [domainsInput, setDomainsInput] = useState('')
  const [deepScan, setDeepScan] = useState(false)
  const [dragActive, setDragActive] = useState(false)
  
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
    setIsScanning(true)
    
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
    }
    
    // For POST with fetch, we can't use standard EventSource easily without external libraries if we send JSON body.
    // However, we can use fetch and read the stream directly.
    fetch(url, options)
      .then(async response => {
        const reader = response.body.getReader()
        const decoder = new TextDecoder('utf-8')
        let buffer = ''
        
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          
          buffer += decoder.decode(value, { stream: true })
          const lines = buffer.split('\n')
          buffer = lines.pop() // keep the incomplete line in the buffer
          
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
              } else if (eventType === 'done') {
                setIsScanning(false)
              }
            }
          }
        }
      })
      .catch(err => {
        console.error('Stream error:', err)
        setIsScanning(false)
      })
  }

  const handleManualSubmit = (e) => {
    e.preventDefault()
    if (!domainsInput.trim()) return
    
    handleStream('http://localhost:8000/api/scan', {
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
    
    handleStream('http://localhost:8000/api/upload', {
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
      'NOT_DETECTED': 'none'
    }
    const c = map[confidence] || 'error'
    return <span className={`badge ${c}`}>{confidence}</span>
  }

  return (
    <>
      <div className="hero">
        <h1>CPQ Detector Pro</h1>
        <p>Enter a domain or upload a CSV file to detect Configure, Price, Quote (CPQ) systems powered by our intelligent scanner.</p>
      </div>
      
      <div className="controls-grid">
        <div className="glass-card">
          <form onSubmit={handleManualSubmit}>
            <div style={{marginBottom: '1rem'}}>
              <h3>Manual Scan</h3>
              <p style={{color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1rem'}}>Enter single or comma-separated domains.</p>
            </div>
            <div className="input-group">
              <input 
                type="text" 
                placeholder="salesforce.com, oracle.com" 
                value={domainsInput}
                onChange={e => setDomainsInput(e.target.value)}
                disabled={isScanning}
              />
              <button className="btn" type="submit" disabled={isScanning || !domainsInput.trim()}>
                {isScanning ? <span className="loader"></span> : 'Scan'}
              </button>
            </div>
            <label style={{display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.9rem'}}>
              <input type="checkbox" checked={deepScan} onChange={e => setDeepScan(e.target.checked)} disabled={isScanning} />
              Enable Deep Scan (follows links to find evidence)
            </label>
          </form>
        </div>

        <div className="glass-card">
          <div style={{marginBottom: '1rem'}}>
            <h3>Bulk Upload</h3>
            <p style={{color: 'var(--text-secondary)', fontSize: '0.9rem'}}>Upload a CSV file containing a domain column.</p>
          </div>
          <label 
            className={`file-upload ${dragActive ? "drag-active" : ""}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="17 8 12 3 7 8"></polyline>
              <line x1="12" y1="3" x2="12" y2="15"></line>
            </svg>
            <p>Drag and drop CSV or click to browse</p>
            <input type="file" accept=".csv" onChange={handleFileUpload} disabled={isScanning} />
          </label>
        </div>
      </div>

      {(results.length > 0 || isScanning) && (
        <div className="results-container glass-card">
          <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem'}}>
            <h3>Results ({results.length})</h3>
            {isScanning && <span style={{display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--primary)'}}><span className="loader" style={{width: '16px', height: '16px', borderWidth: '2px'}}></span> Scanning...</span>}
            {isScanning && <button className="btn" style={{padding: '0.5rem 1rem', background: 'rgba(255,255,255,0.1)'}} onClick={stopScan}>Stop</button>}
          </div>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Status</th>
                  <th>Vendor</th>
                  <th>Confidence</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => (
                  <tr key={i}>
                    <td>
                      {r.final_url ? <a href={r.final_url} target="_blank" rel="noreferrer" style={{color: 'var(--primary)', textDecoration: 'none'}}>{r.domain}</a> : r.domain}
                    </td>
                    <td>{r.error ? <span title={r.error} style={{color: 'var(--danger)', cursor: 'help'}}>Error</span> : (r.http_status || 'N/A')}</td>
                    <td style={{fontWeight: '600'}}>{r.cpq_vendor || '-'}</td>
                    <td>{getConfidenceBadge(r.confidence)}</td>
                    <td className="evidence-cell" title={r.evidence}>{r.evidence || '-'}</td>
                  </tr>
                ))}
                {results.length === 0 && (
                  <tr>
                    <td colSpan="5" style={{textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)'}}>
                      No results yet. Start a scan to see data here.
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
