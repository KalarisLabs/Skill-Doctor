import React, { useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Search, ArrowRight, Clock, RefreshCw } from 'lucide-react';

export function ScanHistory() {
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  const fetchScans = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/scans/history');
      if (res.ok) {
        const data = await res.json();
        setScans(data);
      }
    } catch (err) {
      console.error('Failed to fetch scan history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const filtered = scans.filter((s) => {
    const term = search.toLowerCase();
    return (
      s.scan_id?.toLowerCase().includes(term) ||
      s.source?.toLowerCase().includes(term) ||
      s.risk_level?.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-6">
      {/* Controls */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search by Scan ID or keyword..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 bg-input border border-border rounded text-xs text-foreground focus:outline-none focus:border-primary placeholder:text-slate-500 font-mono"
          />
        </div>
        <Button variant="outline" size="sm" onClick={fetchScans} className="h-8 gap-1.5 text-xs font-mono">
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {loading ? (
        <div className="py-20 text-center space-y-3">
          <div className="w-8 h-8 rounded-full border-2 border-primary border-t-transparent animate-spin mx-auto" />
          <div className="text-xs text-slate-400 font-mono">Querying D1 audit ledger...</div>
        </div>
      ) : filtered.length === 0 ? (
        <div className="console-panel p-12 text-center space-y-3">
          <h3 className="text-sm font-bold text-foreground">No Historical Audits Recorded</h3>
          <p className="text-xs text-slate-400">Run a diagnostic scan to start populating your D1 audit ledger.</p>
          <Button onClick={() => window.location.href = '/scan'} size="sm" className="text-xs">
            Launch Diagnostic Scan
          </Button>
        </div>
      ) : (
        <div className="space-y-2.5">
          {filtered.map((s) => {
            const isDanger = s.risk_level === 'DANGEROUS' || s.risk_level === 'CRITICAL' || s.risk_score >= 7.0;
            const isCaution = s.risk_level === 'CAUTION' || (s.risk_score >= 3.0 && s.risk_score < 7.0);

            return (
              <a
                key={s.scan_id}
                href={`/report/${s.scan_id}`}
                className="console-panel p-3.5 block hover:bg-secondary/60 transition-colors group"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="space-y-1 flex-1 min-w-0">
                    <div className="flex items-center gap-2.5 font-mono text-xs">
                      <span className="font-bold text-foreground">
                        {s.scan_id.substring(0, 10)}...
                      </span>

                      <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${
                        s.status === 'done'
                          ? isDanger
                            ? 'bg-red-950 text-red-400 border border-red-800'
                            : isCaution
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          : 'bg-secondary text-primary border border-border'
                      }`}>
                        {s.status === 'done' ? s.risk_level || 'SAFE' : s.status.toUpperCase()}
                      </span>

                      {s.risk_score !== null && s.risk_score !== undefined && (
                        <span className="text-slate-400">
                          Score: <strong className="text-foreground">{s.risk_score.toFixed(1)}</strong>
                        </span>
                      )}
                    </div>

                    <div className="text-xs text-slate-400 truncate max-w-xl font-mono">
                      {s.source}
                    </div>
                  </div>

                  <div className="flex items-center gap-3 text-xs text-slate-400 font-mono flex-shrink-0">
                    <span>{new Date(s.created_at).toLocaleDateString()} {new Date(s.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-primary group-hover:translate-x-0.5 transition-transform" />
                  </div>
                </div>
              </a>
            );
          })}
        </div>
      )}
    </div>
  );
}
