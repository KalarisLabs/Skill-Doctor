import React, { useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Shield, ArrowLeft, Code, FileCode, CheckCircle2 } from 'lucide-react';

export function ThreatDetail({ threatId }: { threatId: string }) {
  const [threat, setThreat] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchThreat = async () => {
      try {
        const res = await fetch(`/api/threats/${threatId}`);
        if (res.ok) {
          const data = await res.json();
          setThreat(data);
        }
      } catch (err) {
        console.error('Error fetching threat details:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchThreat();
  }, [threatId]);

  if (loading) {
    return (
      <div className="py-20 text-center space-y-3">
        <div className="w-8 h-8 rounded-full border-2 border-primary border-t-transparent animate-spin mx-auto" />
        <div className="text-xs text-slate-400 font-mono">Loading Threat Specification...</div>
      </div>
    );
  }

  if (!threat) {
    return (
      <div className="console-panel p-8 text-center space-y-3">
        <h3 className="text-sm font-bold text-foreground">Threat Indicator Not Found</h3>
        <p className="text-xs text-slate-400">No threat matched identifier {threatId}.</p>
        <Button onClick={() => window.location.href = '/threats'} size="sm" variant="outline" className="text-xs">
          Return to ThreatDB
        </Button>
      </div>
    );
  }

  const isCritical = threat.severity === 'CRITICAL';
  const isHigh = threat.severity === 'HIGH';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="space-y-2 border-b border-border pb-4">
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="font-bold text-primary">{threat.id}</span>
          <span className="text-slate-600">•</span>
          <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${
            isCritical
              ? 'bg-red-950 text-red-400 border border-red-800'
              : isHigh
              ? 'bg-orange-950 text-orange-400 border border-orange-800'
              : 'bg-amber-950 text-amber-400 border border-amber-800'
          }`}>
            {threat.severity}
          </span>
          <span className="text-slate-600">•</span>
          <span className="text-slate-400">{threat.category}</span>
        </div>

        <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground">
          {threat.name}
        </h1>
      </div>

      {/* Description */}
      <div className="console-panel p-5 space-y-2">
        <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300">
          Threat Description & Impact
        </h2>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          {threat.description}
        </p>
      </div>

      {/* Remediation */}
      <div className="console-panel p-5 space-y-2 border-primary/40 bg-secondary/30">
        <h2 className="text-xs font-bold uppercase tracking-wider text-primary">
          Mandated Remediation Policy
        </h2>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          {threat.remediation}
        </p>
      </div>

      {/* Technical Detection Indicators */}
      {threat.indicators && threat.indicators.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Technical Detection Signatures
          </h2>

          <div className="space-y-3">
            {threat.indicators.map((ind: any, i: number) => (
              <div key={i} className="console-panel p-4 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="font-semibold text-foreground">{ind.rule_name || ind.type}</span>
                  <span className="text-[11px]">{ind.type}</span>
                </div>

                {ind.description && (
                  <p className="text-slate-400">{ind.description}</p>
                )}

                {ind.pattern && (
                  <div className="p-3 bg-background border border-border rounded overflow-x-auto">
                    <pre className="text-[11px] text-slate-200">{ind.pattern}</pre>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
