from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from io import BytesIO
from datetime import datetime
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generates detailed analysis reports in various formats"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom styles for the report"""
        # Title style
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=1  # Center alignment
        )
        
        # Subtitle style
        self.subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkred
        )
        
        # Warning style
        self.warning_style = ParagraphStyle(
            'Warning',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.red,
            backColor=colors.mistyrose,
            borderColor=colors.red,
            borderWidth=1,
            borderPadding=5
        )
        
        # Success style
        self.success_style = ParagraphStyle(
            'Success',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.darkgreen,
            backColor=colors.lightgreen,
            borderColor=colors.green,
            borderWidth=1,
            borderPadding=5
        )
    
    async def generate_pdf_report(self, analysis) -> bytes:
        """Generate a comprehensive PDF report for the analysis"""
        try:
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72,
                                  topMargin=72, bottomMargin=18)
            
            # Build story (content)
            story = []
            
            # Add header
            story.extend(self._create_header(analysis))
            story.append(Spacer(1, 20))
            
            # Add executive summary
            story.extend(self._create_executive_summary(analysis))
            story.append(Spacer(1, 20))
            
            # Add file information
            story.extend(self._create_file_info_section(analysis))
            story.append(Spacer(1, 20))
            
            # Add threat assessment
            story.extend(self._create_threat_assessment_section(analysis))
            story.append(Spacer(1, 20))
            
            # Add detailed analysis
            story.extend(self._create_detailed_analysis_section(analysis))
            story.append(PageBreak())
            
            # Add recommendations
            story.extend(self._create_recommendations_section(analysis))
            story.append(Spacer(1, 20))
            
            # Add footer
            story.extend(self._create_footer())
            
            # Build PDF
            doc.build(story)
            
            # Get the value of the BytesIO buffer and return it
            pdf_data = buffer.getvalue()
            buffer.close()
            
            return pdf_data
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")
            raise
    
    def _create_header(self, analysis) -> list:
        """Create report header"""
        story = []
        
        # Main title
        story.append(Paragraph("🛡️ Cybersecurity Analysis Report", self.title_style))
        story.append(Spacer(1, 10))
        
        # Subtitle with file name
        story.append(Paragraph(f"Analysis of: {analysis.filename}", self.subtitle_style))
        story.append(Spacer(1, 10))
        
        # Report metadata
        metadata_data = [
            ['Report Generated:', datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ['Analysis ID:', str(analysis.id)],
            ['File Hash (SHA256):', analysis.file_hash],
            ['Analysis Date:', analysis.upload_time.strftime("%Y-%m-%d %H:%M:%S UTC")]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(metadata_table)
        return story
    
    def _create_executive_summary(self, analysis) -> list:
        """Create executive summary section"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.subtitle_style))
        
        # Threat status
        if analysis.is_malicious:
            threat_color = colors.red if analysis.threat_level == 'CRITICAL' else colors.orange
            summary_text = f"""
            <para textColor="{threat_color}">
            <b>⚠️ THREAT DETECTED</b><br/>
            This file has been identified as malicious with a {analysis.threat_level} threat level.
            Confidence Score: {analysis.confidence_score:.2f if analysis.confidence_score else 0.0}
            </para>
            """
            story.append(Paragraph(summary_text, self.warning_style))
        else:
            summary_text = """
            <para textColor="green">
            <b>✅ NO THREATS DETECTED</b><br/>
            This file appears to be safe based on the current analysis.
            </para>
            """
            story.append(Paragraph(summary_text, self.success_style))
        
        story.append(Spacer(1, 10))
        
        # Analysis summary
        if analysis.analysis_summary:
            story.append(Paragraph("<b>Analysis Summary:</b>", self.styles['Normal']))
            story.append(Paragraph(analysis.analysis_summary, self.styles['Normal']))
        
        return story
    
    def _create_file_info_section(self, analysis) -> list:
        """Create file information section"""
        story = []
        
        story.append(Paragraph("File Information", self.subtitle_style))
        
        file_data = [
            ['File Name:', analysis.filename],
            ['File Size:', f"{analysis.file_size:,} bytes" if analysis.file_size else "Unknown"],
            ['File Type:', analysis.file_type or "Unknown"],
            ['Upload Time:', analysis.upload_time.strftime("%Y-%m-%d %H:%M:%S UTC")],
            ['SHA256 Hash:', analysis.file_hash]
        ]
        
        file_table = Table(file_data, colWidths=[2*inch, 4*inch])
        file_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(file_table)
        return story
    
    def _create_threat_assessment_section(self, analysis) -> list:
        """Create threat assessment section"""
        story = []
        
        story.append(Paragraph("Threat Assessment", self.subtitle_style))
        
        # Threat level indicator
        threat_colors = {
            'LOW': colors.green,
            'MEDIUM': colors.orange,
            'HIGH': colors.red,
            'CRITICAL': colors.darkred
        }
        
        threat_color = threat_colors.get(analysis.threat_level, colors.grey)
        threat_text = f"""
        <para textColor="{threat_color}">
        <b>Threat Level: {analysis.threat_level or 'UNKNOWN'}</b><br/>
        Malicious: {'YES' if analysis.is_malicious else 'NO'}<br/>
        Confidence Score: {analysis.confidence_score:.2f if analysis.confidence_score else 'N/A'}
        </para>
        """
        
        story.append(Paragraph(threat_text, self.styles['Normal']))
        story.append(Spacer(1, 10))
        
        # API Results Summary
        if analysis.virustotal_results:
            vt_data = analysis.virustotal_results
            if vt_data.get('status') == 'found':
                story.append(Paragraph("<b>VirusTotal Results:</b>", self.styles['Normal']))
                vt_summary = f"Detection Ratio: {vt_data.get('detection_ratio', 'N/A')}"
                story.append(Paragraph(vt_summary, self.styles['Normal']))
                story.append(Spacer(1, 5))
        
        return story
    
    def _create_detailed_analysis_section(self, analysis) -> list:
        """Create detailed analysis section"""
        story = []
        
        story.append(Paragraph("Detailed Analysis Results", self.subtitle_style))
        
        # API Results
        if analysis.virustotal_results:
            story.append(Paragraph("<b>VirusTotal Analysis:</b>", self.styles['Heading3']))
            vt_results = analysis.virustotal_results
            if vt_results.get('status') == 'found':
                story.append(Paragraph(f"• Scan Date: {vt_results.get('scan_date', 'Unknown')}", self.styles['Normal']))
                story.append(Paragraph(f"• Detection Ratio: {vt_results.get('detection_ratio', 'N/A')}", self.styles['Normal']))
                story.append(Paragraph(f"• Malicious Detections: {vt_results.get('malicious_count', 0)}", self.styles['Normal']))
            else:
                story.append(Paragraph("• File not found in VirusTotal database", self.styles['Normal']))
            story.append(Spacer(1, 10))
        
        # ML Analysis Results
        if analysis.ml_analysis_results:
            story.append(Paragraph("<b>Machine Learning Analysis:</b>", self.styles['Heading3']))
            ml_results = analysis.ml_analysis_results
            story.append(Paragraph(f"• ML Confidence: {ml_results.get('confidence', 0):.2f}", self.styles['Normal']))
            story.append(Paragraph(f"• Anomaly Detected: {'Yes' if ml_results.get('is_anomaly') else 'No'}", self.styles['Normal']))
            story.append(Paragraph(f"• Model Version: {ml_results.get('model_version', 'Unknown')}", self.styles['Normal']))
            story.append(Spacer(1, 10))
        
        # File Processing Results
        if analysis.detailed_results:
            detailed = analysis.detailed_results
            file_info = detailed.get('file_info', {})
            
            if file_info.get('suspicious_indicators'):
                story.append(Paragraph("<b>Suspicious Indicators Found:</b>", self.styles['Heading3']))
                for indicator in file_info.get('suspicious_indicators', []):
                    story.append(Paragraph(f"• {indicator.replace('_', ' ').title()}", self.styles['Normal']))
                story.append(Spacer(1, 10))
        
        return story
    
    def _create_recommendations_section(self, analysis) -> list:
        """Create recommendations section"""
        story = []
        
        story.append(Paragraph("Recommendations & Next Steps", self.subtitle_style))
        
        # Generate recommendations based on threat level
        if analysis.is_malicious:
            recommendations = [
                "🚨 IMMEDIATE ACTION REQUIRED: This file contains malicious content",
                "🗑️ Delete the file immediately if it's still on your system",
                "🔍 Run a full system scan with updated antivirus software",
                "🔒 Change any passwords that might have been exposed",
                "📱 Check for suspicious network activity or unauthorized access"
            ]
            
            if analysis.threat_level == "CRITICAL":
                recommendations.extend([
                    "⚠️ CRITICAL THREAT: Disconnect from the internet immediately",
                    "🖥️ Consider rebuilding the affected system from clean backups",
                    "📞 Contact your IT security team or cybersecurity professional"
                ])
        else:
            recommendations = [
                "✅ File appears to be safe based on current analysis",
                "🔄 Keep your antivirus software updated for ongoing protection",
                "🛡️ Continue following safe file handling practices",
                "📊 Monitor system behavior after file usage"
            ]
        
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['Normal']))
        
        story.append(Spacer(1, 20))
        
        # General security recommendations
        story.append(Paragraph("<b>General Security Best Practices:</b>", self.styles['Heading3']))
        general_recs = [
            "Keep all software and operating systems updated",
            "Use reputable antivirus software with real-time protection",
            "Be cautious with email attachments and downloads",
            "Regular system backups to secure locations",
            "Employee cybersecurity training and awareness",
            "Implement network segmentation and access controls"
        ]
        
        for rec in general_recs:
            story.append(Paragraph(f"• {rec}", self.styles['Normal']))
        
        return story
    
    def _create_footer(self) -> list:
        """Create report footer"""
        story = []
        
        story.append(Spacer(1, 30))
        story.append(Paragraph("_" * 50, self.styles['Normal']))
        story.append(Spacer(1, 10))
        
        footer_text = """
        <para alignment="center">
        This report was generated by the AI Cybersecurity Fraud Detection System.<br/>
        For questions or additional analysis, please contact your cybersecurity team.<br/>
        <b>Confidential and Proprietary Information</b>
        </para>
        """
        
        story.append(Paragraph(footer_text, self.styles['Normal']))
        
        return story
    
    def generate_json_report(self, analysis) -> Dict[str, Any]:
        """Generate a JSON format report"""
        return {
            "report_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "analysis_id": analysis.id,
                "report_version": "1.0"
            },
            "file_info": {
                "filename": analysis.filename,
                "file_hash": analysis.file_hash,
                "file_size": analysis.file_size,
                "file_type": analysis.file_type,
                "upload_time": analysis.upload_time.isoformat()
            },
            "threat_assessment": {
                "is_malicious": analysis.is_malicious,
                "threat_level": analysis.threat_level,
                "confidence_score": analysis.confidence_score,
                "summary": analysis.analysis_summary
            },
            "analysis_results": {
                "virustotal": analysis.virustotal_results,
                "ml_analysis": analysis.ml_analysis_results,
                "detailed_results": analysis.detailed_results
            },
            "recommendations": self._generate_recommendations_list(analysis)
        }
    
    def _generate_recommendations_list(self, analysis) -> list:
        """Generate a list of recommendations"""
        recommendations = []
        
        if analysis.is_malicious:
            recommendations.extend([
                "Delete the file immediately if still on system",
                "Run full system antivirus scan",
                "Check for unauthorized network activity",
                "Change potentially compromised passwords"
            ])
            
            if analysis.threat_level == "CRITICAL":
                recommendations.extend([
                    "Disconnect from internet immediately",
                    "Contact cybersecurity professionals",
                    "Consider system rebuild from clean backups"
                ])
        else:
            recommendations.extend([
                "File appears safe for use",
                "Continue monitoring system behavior",
                "Keep security software updated"
            ])
        
        return recommendations