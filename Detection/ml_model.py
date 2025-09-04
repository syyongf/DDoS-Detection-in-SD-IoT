import pickle
import numpy as np
import pandas as pd

# data_headers = ['Count_of_Source_IP', 'Port_Count', 'Pair_Count_Ratio',
#        'Packet_Count_Diff', 'Lookup_Count_Diff', 'Protocol',
#        'Average_Packet_Count', 'Average_Byte_Count', 'Packet_Std_Dev',
#        'Byte_Std_Dev', 'Duration_per_Flow']
pickle_files = ["ann_binary.pkl", "knn_binary.pkl", "xgb_binary.pkl", "dt_binary.pkl", "nb_binary.pkl", "lgb_binary.pkl", "lr_binary.pkl", "rf_binary.pkl", "svm_binary.pkl"]
models = []
classifier_weights = {'ann': -0.05031572620325564, 'knn': -0.08215696704673538, 'xgb': 0.42701791955825946, 'dt': 0.41726528327656337, 'nb': -0.0999119969108904, 
                      'lgb': -0.09552457548699501, 'lr': -0.006568460354373834, 'rf': 0.5561907779122968, 'svm': -0.06599625474486952}

min_vals = pd.Series({
    'Count_of_Source_IP': 1.0,
    'Port_Count': 1.0,
    'Pair_Count_Ratio': 0.0,
    'Packet_Count_Diff': 0.0,
    'Lookup_Count_Diff': 0.0,
    'Protocol': 1.0,
    'Average_Packet_Count': 0.0,
    'Average_Byte_Count': 0.0,
    'Packet_Std_Dev': 0.0,
    'Byte_Std_Dev': 0.0,
    'Duration_per_Flow': 0.0
})

max_vals = pd.Series({
    'Count_of_Source_IP': 545.0,
    'Port_Count': 545.0,
    'Pair_Count_Ratio': 5.0,
    'Packet_Count_Diff': 8354853.0,
    'Lookup_Count_Diff': 661525300.0,
    'Protocol': 17.0,
    'Average_Packet_Count': 3327361.0,
    'Average_Byte_Count': 34642430000.0,
    'Packet_Std_Dev': 922909.0,
    'Byte_Std_Dev': 44566670000.0,
    'Duration_per_Flow': 87.12982
})

class classifier:
    def __init__(self):
        self.load_models()


    def load_models(self):
        for filename in pickle_files:
            with open(filename, 'rb') as file:
                model = pickle.load(file)
            model_name = filename.replace("_binary.pkl", "")
            models.append((model_name, model))

    def preprocess_data(self, data):
        normalized_data = (data - min_vals) / (max_vals - min_vals)
        return normalized_data
    
    def predict(self, data):
        weighted_votes = {0: 0, 1: 0}
        predictions = {}
        data = self.preprocess_data(data)
        for name, model in models:
            if name == "ann":
                prediction = np.array((model.predict(data) > 0.5).astype(int))
            else:
                prediction = np.array(model.predict(data))
                prediction = model.predict(data)
            if prediction.ndim > 1:
                prediction = prediction.ravel()
            
            pred_value = prediction[0]
            predictions[name] = pred_value

            weight = classifier_weights.get(name, 1.0)
            weighted_votes[pred_value] += weight
            
        # Get final prediction based on highest weighted vote
        final_prediction = max(weighted_votes, key=weighted_votes.get)
        return final_prediction
    
