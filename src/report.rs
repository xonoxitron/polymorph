use crate::scanner::Scanner;
use crate::detectors::{Detection, Severity};

#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Human,
    Json,
}

pub struct ReportGenerator {
    scanner: Scanner,
    show_offsets: bool,
}

impl ReportGenerator {
    pub fn new(scanner: Scanner) -> Self {
        Self {
            scanner,
            show_offsets: false,
        }
    }

    pub fn set_show_offsets(&mut self, show: bool) {
        self.show_offsets = show;
    }

    pub fn get_risk_score(&self) -> u32 {
        crate::detectors::calculate_risk_score(&self.scanner.detections, &self.scanner.binary_type)
    }

    pub fn generate(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Human => self.generate_human_report(),
            OutputFormat::Json => self.generate_json_report(),
        }
    }

    fn generate_human_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str("═══ DETECTION REPORT ═══\n\n");
        report.push_str(&format!("Binary Type: {:?}\n\n", self.scanner.binary_type));
        report.push_str(&format!("Total Detections: {}\n", self.scanner.detections.len()));
        
        if !self.scanner.detections.is_empty() {
            let max_severity = self.scanner.detections.iter()
                .map(|d| &d.severity)
                .max()
                .unwrap();
            report.push_str(&format!("Maximum Severity: {:?}\n\n", max_severity));
        }

        let mut by_category = std::collections::HashMap::new();
        for detection in &self.scanner.detections {
            *by_category.entry(format!("{:?}", detection.category)).or_insert(0) += 1;
        }

        if !by_category.is_empty() {
            report.push_str("Category Breakdown:\n");
            for (cat, count) in by_category {
                report.push_str(&format!("  {}: {} findings\n", cat, count));
            }
            report.push_str("\n");
        }

        let critical: Vec<_> = self.scanner.detections.iter()
            .filter(|d| d.severity == Severity::Critical)
            .collect();
        let high: Vec<_> = self.scanner.detections.iter()
            .filter(|d| d.severity == Severity::High)
            .collect();
        
        if !critical.is_empty() {
            report.push_str("═══ CRITICAL FINDINGS ═══\n\n");
            for det in critical {
                report.push_str(&self.format_detection(det));
            }
        }

        if !high.is_empty() {
            report.push_str("═══ HIGH SEVERITY ═══\n\n");
            for det in high {
                report.push_str(&self.format_detection(det));
            }
        }

        let risk_score = self.get_risk_score();
        report.push_str("\n═══ RISK ASSESSMENT ═══\n\n");
        report.push_str(&format!("Risk Score: {}/100\n", risk_score));
        
        let verdict = match risk_score {
            0..=20 => "✅ CLEAN",
            21..=40 => "⚠️  LOW RISK",
            41..=60 => "⚠️  MEDIUM RISK",
            61..=80 => "⚠️  HIGH RISK",
            _ => "⚠️  CRITICAL THREAT",
        };
        report.push_str(&format!("Verdict: {}\n", verdict));

        report
    }

    fn format_detection(&self, det: &Detection) -> String {
        let mut s = format!("[{:?}] {:?}: {}\n", 
            det.severity, det.category, det.description);
        
        if self.show_offsets {
            if let Some(offset) = det.offset {
                s.push_str(&format!("  └─ Offset: 0x{:04X}\n", offset));
            }
        }
        
        s.push('\n');
        s
    }

    fn generate_json_report(&self) -> String {
        format!("{{\"binary_type\":\"{:?}\",\"detections\":{},\"risk_score\":{}}}",
            self.scanner.binary_type,
            self.scanner.detections.len(),
            self.get_risk_score()
        )
    }
}
