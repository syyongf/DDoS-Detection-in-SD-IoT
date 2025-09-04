# DDoS-Detection-in-SD-IoT
This repo contains the code related to paper - "DDoS Detection in SD-IoT: A GA-Optimized Weighted Majority Vote Model Using SDN Simulated Datasets". All related code are categorized into following:

* Dataset Generation: this includes the python scripts for generating normal and attack traffic in simulated network, capturing these traffic and writing them into .csv files.

* Dataset: two generated datasets, one is for binary prediction, the other one is for multi-class prediction.

* Model training and testing: This includes the code about training and testing 9 basic classifiers and GA-optimized weighted majority voting ensemble model using generated datasets.

* Detection: Python scripts implemented in controller for real-time detecting and monitoring, including packet inspection, trained models and other network functionalities.

* Trained Models: 9 .pkl files contains well-trained classifiers, in order to reduce the running burden for controller.
