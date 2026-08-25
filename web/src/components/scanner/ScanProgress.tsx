import React, { useEffect, useState, useRef } from 'react';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Loader2, 
  Terminal,
  Clock,
  ShieldAlert
} from 'lucide-react';

interface ScanProgressProps {
  scanId: string;
}

type LayerState = 'pending' | 'running' | 'done' | 'unavailable' | 'error';

interface ScanState {
  status: string;
  intake: LayerState;
  static: LayerState;
  semantic: LayerState;
  sandbox: LayerState;
  threat_intel: LayerState;
  findings: number;
  findingsList: Array<{ id?: string; severity: string; category: string; description: string }>;
  reportUrl?: string;
  error?: string;
  lifecycleState: string;
}

export function ScanProgress({ scanId }: ScanProgressProps) {
  const [state, setState] = useState<ScanState>({
    status: 'queued',
    intake: 'pending',
    static: 'pending',
    semantic: 'pending',
    sandbox: 'pending',
    threat_intel: 'pending',
    findings: 0,
    findingsList: [],
    lifecycleState: 'accepted'
  });

  const eventSourceRef = useRef<EventSource | null>(null);
  const pollingTimerRef = useRef<any>(null);

  useEffect(() => {
    let isCompleted = false;

    const startPollingFallback = () => {
      if (pollingTimerRef.current || isCompleted) return;
      
      pollingTimerRef.current = setInterval(async () => {
        try {
          const res = await fetch(`/api/scans/${scanId}/report`);
          if (res.ok) {
            const data = await res.json();
            if (data.status === 'done') {
              isCompleted = true;
              clearInterval(pollingTimerRef.current);
              setState(prev => ({
                ...prev,
                status: 'done',
                static: 'done',
                semantic: prev.semantic === 'running' ? 'done' : prev.semantic,
                sandbox: prev.sandbox === 'running' ? 'done' : prev.sandbox,
                threat_intel: 'done',
                reportUrl: `/report/${scanId}`
              }));
              setTimeout(() => {
                window.location.href = `/report/${scanId}`;
              }, 1000);
            }
          }
        } catch {
          // ignore transient poll errors
        }
      }, 2000);
    };

    try {
      const eventSource = new EventSource(`/api/scans/${scanId}/stream`);
      eventSourceRef.current = eventSource;

      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          setState((prev) => {
            const newState = { ...prev };
            
            if (data.type === 'lifecycle_update') {
              newState.lifecycleState = data.state;
              if (data.state === 'analyzing') {
                newState.status = 'running';
                if (newState.intake === 'pending') newState.intake = 'done';
              }
            } else if (data.type === 'stage_started') {
              const layer = data.layer.toLowerCase();
              if (layer === 'threat_db' || layer === 'threat_intel') newState.threat_intel = 'running';
              else if (layer === 'static') newState.static = 'running';
              else if (layer === 'semantic') newState.semantic = 'running';
              else if (layer === 'sandbox') newState.sandbox = 'running';
            } else if (data.type === 'stage_completed') {
              const layer = data.layer.toLowerCase();
              if (layer === 'threat_db' || layer === 'threat_intel') newState.threat_intel = 'done';
              else if (layer === 'static') newState.static = 'done';
              else if (layer === 'semantic') newState.semantic = 'done';
              else if (layer === 'sandbox') newState.sandbox = 'done';
            } else if (data.type === 'stage_failed') {
              const layer = data.layer.toLowerCase();
              if (layer === 'threat_db' || layer === 'threat_intel') newState.threat_intel = 'unavailable';
              else if (layer === 'static') newState.static = 'error';
              else if (layer === 'semantic') newState.semantic = 'unavailable';
              else if (layer === 'sandbox') newState.sandbox = 'unavailable';
            } else if (data.type === 'finding_detected') {
              newState.findings += 1;
              if (data.finding) {
                newState.findingsList = [data.finding, ...newState.findingsList].slice(0, 5);
              }
            } else if (data.type === 'scan_completed') {
              isCompleted = true;
              newState.status = 'done';
              newState.intake = 'done';
              newState.static = 'done';
              newState.threat_intel = 'done';
              newState.reportUrl = `/report/${scanId}`;
              eventSource.close();
              if (pollingTimerRef.current) clearInterval(pollingTimerRef.current);
              
              setTimeout(() => {
                window.location.href = `/report/${scanId}`;
              }, 1000);
            } else if (data.type === 'scan_failed') {
              isCompleted = true;
              newState.status = 'error';
              newState.error = data.error || 'Scan analysis failed.';
              eventSource.close();
              if (pollingTimerRef.current) clearInterval(pollingTimerRef.current);
            }

            return newState;
          });
        } catch (err) {
          console.debug('Received SSE frame:', err);
        }
      };

      eventSource.onerror = () => {
        startPollingFallback();
      };
    } catch {
      startPollingFallback();
    }

    return () => {
      if (eventSourceRef.current) eventSourceRef.current.close();
      if (pollingTimerRef.current) clearInterval(pollingTimerRef.current);
    };
  }, [scanId]);

  const getProgress = () => {
    if (state.status === 'done') return 100;
    if (state.status === 'error') return 0;
    
    let completed = 0;
    const layers = ['intake', 'threat_intel', 'static', 'semantic', 'sandbox'];
    layers.forEach(layer => {
      const ls = (state as any)[layer];
      if (ls === 'done' || ls === 'unavailable') completed += 1;
      else if (ls === 'running') completed += 0.5;
    });
    
    return Math.max(15, Math.floor((completed / layers.length) * 100));
  };

  const LayerRow = ({ name, description, layerState }: { name: string, description: string, layerState: LayerState }) => {
    return (
      <div className="flex items-center justify-between py-2.5 px-3 rounded bg-background border border-border text-xs">
        <div className="flex items-center space-x-3">
          <div className="flex-shrink-0">
            {layerState === 'pending' && <span className="block w-2 h-2 rounded-full bg-slate-600" />}
            {layerState === 'running' && <Loader2 className="w-3.5 h-3.5 text-primary animate-spin" />}
            {layerState === 'done' && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
            {layerState === 'unavailable' && <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />}
            {layerState === 'error' && <XCircle className="w-3.5 h-3.5 text-red-400" />}
          </div>
          <div>
            <div className="font-semibold text-foreground">{name}</div>
            <div className="text-[11px] text-slate-400">{description}</div>
          </div>
        </div>
        <div>
          {layerState === 'pending' && <span className="font-mono text-[10px] text-slate-500 uppercase">QUEUED</span>}
          {layerState === 'running' && <span className="font-mono text-[10px] text-primary uppercase font-bold">ANALYZING</span>}
          {layerState === 'done' && <span className="font-mono text-[10px] text-emerald-400 uppercase font-bold">VERIFIED</span>}
          {layerState === 'unavailable' && <span className="font-mono text-[10px] text-amber-400 uppercase">ISOLATED</span>}
          {layerState === 'error' && <span className="font-mono text-[10px] text-red-400 uppercase font-bold">FAILED</span>}
        </div>
      </div>
    );
  };

  return (
    <div className="console-panel p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border pb-4">
        <div>
          <h2 className="text-base font-bold text-foreground">Diagnostic Execution Telemetry</h2>
          <div className="text-xs font-mono text-slate-400 mt-0.5">
            Scan ID: <span className="text-foreground">{scanId}</span>
          </div>
        </div>
        <Badge variant="outline" className="font-mono text-xs uppercase px-2.5 py-0.5">
          {state.status}
        </Badge>
      </div>

      {state.status === 'error' ? (
        <div className="bg-red-950/40 border border-red-800 text-red-300 p-4 rounded text-xs flex items-center gap-3">
          <XCircle className="w-5 h-5 flex-shrink-0 text-red-400" />
          <div>
            <div className="font-bold">Scan Execution Failed</div>
            <div className="text-slate-400 mt-0.5">{state.error || 'An unexpected runtime error occurred.'}</div>
          </div>
        </div>
      ) : (
        <div className="space-y-2">
          <div className="flex justify-between items-center text-xs font-medium">
            <span className="text-slate-400">Pipeline Execution Progress</span>
            <span className="font-mono font-bold text-foreground">{getProgress()}%</span>
          </div>
          <Progress value={getProgress()} className="h-1.5 rounded bg-secondary" />
        </div>
      )}

      {/* Layer Checklist */}
      <div className="space-y-2">
        <LayerRow name="Intake & Normalization" description="Payload extraction & cryptographic SHA-256 generation" layerState={state.intake} />
        <LayerRow name="Layer 4: ThreatDB Intelligence" description="Canonical indicator query & CVE cross-reference" layerState={state.threat_intel} />
        <LayerRow name="Layer 1: Static AST & YARA-X" description="Syntax tree traversal and forbidden API inspection" layerState={state.static} />
        <LayerRow name="Layer 2: Semantic BYOK Inference" description="Prompt injection & adversarial intent evaluation" layerState={state.semantic} />
        <LayerRow name="Layer 3: Sandbox Egress Boundaries" description="Isolated compute & network egress inspection" layerState={state.sandbox} />
      </div>

      {/* Live Findings Interceptor */}
      {state.findings > 0 && (
        <div className="p-3.5 rounded bg-amber-950/20 border border-amber-800/60 space-y-2 text-xs">
          <div className="flex items-center justify-between text-amber-400 font-semibold">
            <span className="flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4" />
              <span>Detections Flagged ({state.findings})</span>
            </span>
            <span className="font-mono text-[10px] uppercase font-bold">In-Flight</span>
          </div>

          <div className="space-y-1">
            {state.findingsList.map((finding, idx) => (
              <div key={idx} className="flex items-center justify-between p-2 rounded bg-background/80 border border-border text-[11px] font-mono">
                <span className="text-foreground truncate max-w-xs">{finding.category}</span>
                <span className="text-red-400 font-bold uppercase">{finding.severity}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {state.status === 'done' && (
        <div className="p-3 rounded bg-emerald-950/30 border border-emerald-800 text-center text-xs text-emerald-400 font-medium">
          Audit complete. Redirecting to forensic report...
        </div>
      )}
    </div>
  );
}
