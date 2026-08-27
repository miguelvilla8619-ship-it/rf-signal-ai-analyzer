db.createDatabase();

db = db.getSiblingDB('rf-signals');

db.createCollection('signals');
db.createCollection('threats');
db.createCollection('scans');
db.createCollection('detections');

db.signals.createIndex({ timestamp: 1 });
db.signals.createIndex({ mac_address: 1 });
db.signals.createIndex({ device_type: 1 });

db.threats.createIndex({ timestamp: 1 });
db.threats.createIndex({ threat_level: 1 });
db.threats.createIndex({ device_id: 1 });

db.scans.createIndex({ startTime: 1 });
db.scans.createIndex({ status: 1 });

db.detections.createIndex({ timestamp: 1 });
db.detections.createIndex({ threatType: 1 });

print('Database initialized successfully');
