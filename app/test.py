from modules.threat_find.ThreatFind import ThreatFind
flow_feature = ThreatFind("test2.pcap",model_path="model/randomforest_model.pkl",pipeline_path="model/preprocessing_pipeline.pkl")
flow_feature.parse_csv("have_threat.csv")
# print(flow_feature.getFeatures())