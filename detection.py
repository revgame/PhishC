import numpy as np
import pickle
import joblib

import feature_extraction


def getResult(url):
    # Loading the model using pickle
    loaded_model = joblib.load("/Users/rowlandndoma-egba/PycharmProjects/PhishC/jobFinalized_model.sav", 'r')

    new_value = feature_extraction.generate_data_set(url)
    new_value = np.array(new_value).reshape(1, -1)
    print(new_value)

    prediction = loaded_model.predict(new_value)
    print(prediction)
    if prediction == 1:
        return "Phishing URL"
    else:
        return "Legitimate URL"

