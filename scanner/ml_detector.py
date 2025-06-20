import pickle
import pefile
import os

def extract_features(file_path):
    try:
        pe = pefile.PE(file_path)
        features = {
            'NumberOfSections': len(pe.sections),
            'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
            'FileSize': os.path.getsize(file_path)
        }
        return [list(features.values())]
    except:
        return [[0, 0, 0]]

def load_model(model_path='models/model.pkl'):
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    return model

def predict_file(file_path):
    model = load_model()
    features = extract_features(file_path)
    result = model.predict(features)
    return result[0]
