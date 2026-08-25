import React, { useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Search, ArrowRight, Shield } from 'lucide-react';

export function ThreatList() {
  const [threats, setThreats] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const res = await fetch('/api/threats');
        if (res.ok) {
          const data = await res.json();
          setThreats(data);
        }
      } catch (err) {
        console.error('Failed to fetch threats:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchThreats();
  }, []);

  const filtered = threats.filter((t) => {
    const term = search.toLowerCase();
    const matchesSearch = 
      t.id?.toLowerCase().includes(term) ||
      t.name?.toLowerCase().includes(term) ||
      t.category?.toLowerCase().includes(term) ||
      t.description?.toLowerCase().includes(term);

    const matchesSeverity = filterSeverity === 'ALL' || t.severity === filterSeverity;
    return matchesSearch && matchesSeverity;
  });

  if (loading) {
    return (
      <div className="py-20 text-center space-y-3">
        <div className="w-8 h-8 rounded-full border-2 border-primary border-t-transparent animate-spin mx-auto" />
        <div className="text-xs text-slate-400 font-mono">Querying ThreatDB canonical database...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Filter by ID, category, or CVE..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 bg-input border border-border rounded text-xs text-foreground focus:outline-none focus:border-primary placeholder:text-slate-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-1 text-xs font-mono">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-3 py-1 rounded transition-colors ${
                filterSeverity === sev
                  ? 'bg-secondary text-foreground font-semibold'
                  : 'text-slate-400 hover:text-foreground'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Dense Threat Indicator Table / Cards */}
      <div className="space-y-3">
        {filtered.map((t) => {
          const isCritical = t.severity === 'CRITICAL';
          const isHigh = t.severity === 'HIGH';

          return (
            <a 
              key={t.id} 
              href={`/threats/${t.id}`} 
              className="console-panel p-4 block hover:bg-secondary/60 transition-colors group"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1.5 max-w-3xl">
                  <div className="flex items-center gap-2.5 font-mono text-xs">
                    <span className="font-bold text-primary">{t.id}</span>
                    <span className="text-slate-600">•</span>
                    <span className="text-slate-400">{t.category}</span>
                    <span className="text-slate-600">•</span>
                    <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${
                      isCritical
                        ? 'bg-red-950 text-red-400 border border-red-800'
                        : isHigh
                        ? 'bg-orange-950 text-orange-400 border border-orange-800'
                        : 'bg-amber-950 text-amber-400 border border-amber-800'
                    }`}>
                      {t.severity}
                    </span>
                  </div>

                  <h3 className="text-sm font-bold text-foreground group-hover:text-primary transition-colors">
                    {t.name}
                  </h3>

                  <p className="text-xs text-slate-300 leading-relaxed">
                    {t.description}
                  </p>
                </div>

                <div className="flex items-center gap-1 text-xs text-primary font-medium flex-shrink-0">
                  <span>Inspect Spec</span>
                  <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
                </div>
              </div>
            </a>
          );
        })}
      </div>
    </div>
  );
}
