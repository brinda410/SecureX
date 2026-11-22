import mongoose from "mongoose";
import PlayCipherEvent from "../models/PlayCipherEvent.js";

const VALID_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

export const getSecurityEvents = async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(
      100,
      Math.max(1, parseInt(req.query.limit, 10) || 20)
    );

    const filter = {};

    if (req.query.severity) {
      const severity = String(req.query.severity).toUpperCase();

      if (!VALID_SEVERITIES.includes(severity)) {
        return res.status(400).json({
          success: false,
          message: "Invalid severity filter."
        });
      }

      filter.severity = severity;
    }

    if (req.query.source) {
      const source = String(req.query.source).toUpperCase();

      if (!["HTTP", "AUTH", "SOCKET", "SYSTEM"].includes(source)) {
        return res.status(400).json({
          success: false,
          message: "Invalid event source."
        });
      }

      filter.source = source;
    }

    if (req.query.from || req.query.to) {
      filter.detectedAt = {};

      if (req.query.from) {
        const from = new Date(req.query.from);

        if (Number.isNaN(from.getTime())) {
          return res.status(400).json({
            success: false,
            message: "Invalid start date."
          });
        }

        filter.detectedAt.$gte = from;
      }

      if (req.query.to) {
        const to = new Date(req.query.to);

        if (Number.isNaN(to.getTime())) {
          return res.status(400).json({
            success: false,
            message: "Invalid end date."
          });
        }

        filter.detectedAt.$lte = to;
      }
    }

    const [events, total] = await Promise.all([
      PlayCipherEvent.find(filter)
        .select("-metadata")
        .populate("userId", "name email")
        .sort({ detectedAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),

      PlayCipherEvent.countDocuments(filter)
    ]);

    return res.status(200).json({
      success: true,
      events,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error("Security events error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve security events."
    });
  }
};

export const getSecuritySummary = async (req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const [total, last24Hours, severityCounts, sourceCounts, latestEvent] =
      await Promise.all([
        PlayCipherEvent.countDocuments(),

        PlayCipherEvent.countDocuments({
          detectedAt: { $gte: since }
        }),

        PlayCipherEvent.aggregate([
          {
            $group: {
              _id: "$severity",
              count: { $sum: 1 }
            }
          }
        ]),

        PlayCipherEvent.aggregate([
          {
            $group: {
              _id: "$source",
              count: { $sum: 1 }
            }
          }
        ]),

        PlayCipherEvent.findOne()
          .select("type severity source detectedAt")
          .sort({ detectedAt: -1 })
          .lean()
      ]);

    const severity = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0
    };

    const sources = {
      HTTP: 0,
      AUTH: 0,
      SOCKET: 0,
      SYSTEM: 0
    };

    severityCounts.forEach(item => {
      severity[item._id] = item.count;
    });

    sourceCounts.forEach(item => {
      sources[item._id] = item.count;
    });

    return res.status(200).json({
      success: true,
      summary: {
        totalEvents: total,
        eventsLast24Hours: last24Hours,
        severity,
        sources,
        latestEvent
      }
    });
  } catch (error) {
    console.error("Security summary error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve security summary."
    });
  }
};