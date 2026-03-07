import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Risk Analysis Module
 * Analyzes vulnerability scan results and calculates risk scores
 */
public class RiskAnalyzer {

    private static final Map<String, Integer> SEVERITY_WEIGHTS = Map.of(
            "CRITICAL", 10,
            "HIGH", 7,
            "MEDIUM", 4,
            "LOW", 1,
            "UNKNOWN", 0
    );

    /**
     * Main entry point for risk analysis
     */
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java RiskAnalyzer <scan_results.json>");
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args.length > 1 ? args[1] : "risk_analysis_output.json";

        try {
            RiskAnalyzer analyzer = new RiskAnalyzer();
            JsonObject results = analyzer.analyzeScanResults(inputFile);
            analyzer.saveResults(results, outputFile);

            System.out.println("Risk analysis completed successfully!");
            System.out.println("Output saved to: " + outputFile);

            // Print summary
            analyzer.printSummary(results);

        } catch (IOException e) {
            System.err.println("Error reading scan results: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Error during analysis: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Analyze scan results and calculate risk metrics
     */
    public JsonObject analyzeScanResults(String inputFile) throws IOException {
        // Read scan results
        String content = new String(Files.readAllBytes(Paths.get(inputFile)));
        JsonObject scanData = JsonParser.parseString(content).getAsJsonObject();

        // Extract data
        JsonArray vulnerabilities = scanData.has("vulnerabilities") ?
                scanData.getAsJsonArray("vulnerabilities") : new JsonArray();

        JsonArray services = scanData.has("services") ?
                scanData.getAsJsonArray("services") : new JsonArray();

        // Calculate risk metrics
        RiskMetrics metrics = calculateRiskMetrics(vulnerabilities);

        // Calculate host-based risks
        Map<String, HostRisk> hostRisks = calculateHostRisks(vulnerabilities);

        // Generate remediation priorities
        List<RemediationItem> priorities = generateRemediationPriorities(vulnerabilities);

        // Build result JSON
        JsonObject result = new JsonObject();
        result.add("risk_metrics", metrics.toJson());
        result.add("host_risks", hostRisksToJson(hostRisks));
        result.add("remediation_priorities", remediationToJson(priorities));
        result.addProperty("analysis_timestamp", System.currentTimeMillis());

        return result;
    }

    /**
     * Calculate overall risk metrics
     */
    private RiskMetrics calculateRiskMetrics(JsonArray vulnerabilities) {
        RiskMetrics metrics = new RiskMetrics();

        List<Double> cvssScores = new ArrayList<>();
        Map<String, Integer> severityCounts = new HashMap<>();

        for (int i = 0; i < vulnerabilities.size(); i++) {
            JsonObject vuln = vulnerabilities.get(i).getAsJsonObject();

            // Extract severity
            String severity = vuln.has("severity") ?
                    vuln.get("severity").getAsString() : "UNKNOWN";
            severityCounts.put(severity, severityCounts.getOrDefault(severity, 0) + 1);

            // Extract CVSS score
            if (vuln.has("cvss_score")) {
                double cvss = vuln.get("cvss_score").getAsDouble();
                cvssScores.add(cvss);
            }
        }

        metrics.totalVulnerabilities = vulnerabilities.size();
        metrics.severityCounts = severityCounts;

        if (!cvssScores.isEmpty()) {
            metrics.averageCvss = cvssScores.stream()
                    .mapToDouble(Double::doubleValue)
                    .average()
                    .orElse(0.0);

            metrics.maxCvss = cvssScores.stream()
                    .mapToDouble(Double::doubleValue)
                    .max()
                    .orElse(0.0);
        }

        // Calculate overall risk score (0-100)
        metrics.riskScore = calculateOverallRiskScore(severityCounts, cvssScores);

        return metrics;
    }

    /**
     * Calculate overall risk score
     */
    private double calculateOverallRiskScore(Map<String, Integer> severityCounts,
                                             List<Double> cvssScores) {
        if (severityCounts.isEmpty()) {
            return 0.0;
        }

        // Weighted severity score
        int weightedSum = severityCounts.entrySet().stream()
                .mapToInt(e -> SEVERITY_WEIGHTS.getOrDefault(e.getKey(), 0) * e.getValue())
                .sum();

        int totalVulns = severityCounts.values().stream().mapToInt(Integer::intValue).sum();

        double severityScore = (double) weightedSum / Math.max(1, totalVulns) * 10;

        // CVSS-based score
        double cvssScore = 0.0;
        if (!cvssScores.isEmpty()) {
            cvssScore = cvssScores.stream()
                    .mapToDouble(Double::doubleValue)
                    .average()
                    .orElse(0.0) * 10;
        }

        // Combined risk score (weighted average)
        double riskScore = (severityScore * 0.6 + cvssScore * 0.4);

        return Math.min(100.0, riskScore);
    }

    /**
     * Calculate risk for each host
     */
    private Map<String, HostRisk> calculateHostRisks(JsonArray vulnerabilities) {
        Map<String, HostRisk> hostRisks = new HashMap<>();

        for (int i = 0; i < vulnerabilities.size(); i++) {
            JsonObject vuln = vulnerabilities.get(i).getAsJsonObject();

            String ip = vuln.has("ip") ? vuln.get("ip").getAsString() : "unknown";
            String severity = vuln.has("severity") ? vuln.get("severity").getAsString() : "UNKNOWN";
            double cvss = vuln.has("cvss_score") ? vuln.get("cvss_score").getAsDouble() : 0.0;

            HostRisk risk = hostRisks.computeIfAbsent(ip, k -> new HostRisk(ip));
            risk.addVulnerability(severity, cvss);
        }

        // Calculate risk scores for each host
        hostRisks.values().forEach(HostRisk::calculateRiskScore);

        return hostRisks;
    }

    /**
     * Generate remediation priorities
     */
    private List<RemediationItem> generateRemediationPriorities(JsonArray vulnerabilities) {
        List<RemediationItem> items = new ArrayList<>();

        for (int i = 0; i < vulnerabilities.size(); i++) {
            JsonObject vuln = vulnerabilities.get(i).getAsJsonObject();

            RemediationItem item = new RemediationItem();
            item.cveId = vuln.has("cve_id") ? vuln.get("cve_id").getAsString() : "N/A";
            item.ip = vuln.has("ip") ? vuln.get("ip").getAsString() : "N/A";
            item.port = vuln.has("port") ? vuln.get("port").getAsInt() : 0;
            item.service = vuln.has("product") ? vuln.get("product").getAsString() : "N/A";
            item.severity = vuln.has("severity") ? vuln.get("severity").getAsString() : "UNKNOWN";
            item.cvssScore = vuln.has("cvss_score") ? vuln.get("cvss_score").getAsDouble() : 0.0;
            item.description = vuln.has("description") ? vuln.get("description").getAsString() : "";

            // Calculate priority score
            item.priorityScore = calculatePriorityScore(item);

            items.add(item);
        }

        // Sort by priority score (descending)
        items.sort((a, b) -> Double.compare(b.priorityScore, a.priorityScore));

        return items;
    }

    /**
     * Calculate priority score for remediation
     */
    private double calculatePriorityScore(RemediationItem item) {
        double severityWeight = SEVERITY_WEIGHTS.getOrDefault(item.severity, 0);
        double cvssWeight = item.cvssScore;

        // Combined priority score
        return (severityWeight * 0.5 + cvssWeight * 0.5);
    }

    /**
     * Save results to JSON file
     */
    private void saveResults(JsonObject results, String outputFile) throws IOException {
        Gson gson = new Gson();
        String json = gson.toJson(results);

        Files.write(Paths.get(outputFile), json.getBytes());
    }

    /**
     * Print summary to console
     */
    private void printSummary(JsonObject results) {
        System.out.println("\n========================================");
        System.out.println("       RISK ANALYSIS SUMMARY");
        System.out.println("========================================\n");

        JsonObject metrics = results.getAsJsonObject("risk_metrics");

        System.out.println("Overall Risk Score: " +
                String.format("%.2f", metrics.get("risk_score").getAsDouble()) + "/100");
        System.out.println("Total Vulnerabilities: " +
                metrics.get("total_vulnerabilities").getAsInt());
        System.out.println("Average CVSS: " +
                String.format("%.2f", metrics.get("average_cvss").getAsDouble()));
        System.out.println("Max CVSS: " +
                String.format("%.2f", metrics.get("max_cvss").getAsDouble()));

        System.out.println("\n========================================\n");
    }

    /**
     * Convert host risks to JSON
     */
    private JsonArray hostRisksToJson(Map<String, HostRisk> hostRisks) {
        JsonArray array = new JsonArray();

        // Sort by risk score
        List<HostRisk> sortedRisks = hostRisks.values().stream()
                .sorted((a, b) -> Double.compare(b.riskScore, a.riskScore))
                .collect(Collectors.toList());

        for (HostRisk risk : sortedRisks) {
            array.add(risk.toJson());
        }

        return array;
    }

    /**
     * Convert remediation items to JSON
     */
    private JsonArray remediationToJson(List<RemediationItem> items) {
        JsonArray array = new JsonArray();

        for (int i = 0; i < Math.min(items.size(), 50); i++) {
            array.add(items.get(i).toJson());
        }

        return array;
    }

    /**
     * Risk metrics data class
     */
    static class RiskMetrics {
        int totalVulnerabilities;
        double averageCvss;
        double maxCvss;
        double riskScore;
        Map<String, Integer> severityCounts = new HashMap<>();

        JsonObject toJson() {
            JsonObject obj = new JsonObject();
            obj.addProperty("total_vulnerabilities", totalVulnerabilities);
            obj.addProperty("average_cvss", averageCvss);
            obj.addProperty("max_cvss", maxCvss);
            obj.addProperty("risk_score", riskScore);

            JsonObject severity = new JsonObject();
            severityCounts.forEach(severity::addProperty);
            obj.add("severity_distribution", severity);

            return obj;
        }
    }

    /**
     * Host risk data class
     */
    static class HostRisk {
        String ip;
        int vulnerabilityCount;
        Map<String, Integer> severityCounts = new HashMap<>();
        List<Double> cvssScores = new ArrayList<>();
        double riskScore;

        HostRisk(String ip) {
            this.ip = ip;
        }

        void addVulnerability(String severity, double cvss) {
            vulnerabilityCount++;
            severityCounts.put(severity, severityCounts.getOrDefault(severity, 0) + 1);
            cvssScores.add(cvss);
        }

        void calculateRiskScore() {
            if (vulnerabilityCount == 0) {
                riskScore = 0.0;
                return;
            }

            int weightedSum = severityCounts.entrySet().stream()
                    .mapToInt(e -> SEVERITY_WEIGHTS.getOrDefault(e.getKey(), 0) * e.getValue())
                    .sum();

            double avgCvss = cvssScores.stream()
                    .mapToDouble(Double::doubleValue)
                    .average()
                    .orElse(0.0);

            riskScore = Math.min(100.0,
                    (weightedSum / (double) vulnerabilityCount * 10 * 0.6) +
                    (avgCvss * 10 * 0.4));
        }

        JsonObject toJson() {
            JsonObject obj = new JsonObject();
            obj.addProperty("ip", ip);
            obj.addProperty("vulnerability_count", vulnerabilityCount);
            obj.addProperty("risk_score", riskScore);

            JsonObject severity = new JsonObject();
            severityCounts.forEach(severity::addProperty);
            obj.add("severity_distribution", severity);

            return obj;
        }
    }

    /**
     * Remediation item data class
     */
    static class RemediationItem {
        String cveId;
        String ip;
        int port;
        String service;
        String severity;
        double cvssScore;
        String description;
        double priorityScore;

        JsonObject toJson() {
            JsonObject obj = new JsonObject();
            obj.addProperty("cve_id", cveId);
            obj.addProperty("ip", ip);
            obj.addProperty("port", port);
            obj.addProperty("service", service);
            obj.addProperty("severity", severity);
            obj.addProperty("cvss_score", cvssScore);
            obj.addProperty("priority_score", priorityScore);

            String desc = description.length() > 100 ?
                    description.substring(0, 100) + "..." : description;
            obj.addProperty("description", desc);

            return obj;
        }
    }
}

