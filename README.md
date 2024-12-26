# Network Intrusion Detection using Supervised Machine Learning Techniques

This project implements a **Network Intrusion Detection System (NIDS)** using **Supervised Machine Learning** techniques with **Feature Selection**. The system uses two models:

1. **Support Vector Machine (SVM)**
2. **Artificial Neural Network (ANN)**

The project uses the **NSL-KDD dataset** and provides a graphical user interface (GUI) built with **Tkinter** for ease of use.

## Features

- **Dataset Preprocessing**: Removes non-numeric values and generates a cleaned dataset (`clean.txt`).
- **Model Training**: Trains models (SVM and ANN) to classify network traffic as "normal" or "anomalous."
- **Prediction**: Detects attacks by testing the trained model with new data.
- **Feature Selection**: Uses `SelectKBest` for feature selection to improve model performance.
- **Visualization**: Plots a graph comparing the accuracy of the SVM and ANN models.
  
## Technologies Used

- Python
- Tkinter (for GUI)
- scikit-learn (for SVM and feature selection)
- Keras (for ANN model)
- pandas (for data handling)
- numpy (for numerical operations)
- matplotlib (for plotting accuracy graph)
  
## Installation

### Prerequisites

To run the project, ensure you have Python installed and the following libraries:

```bash
pip install tkinter
pip install scikit-learn
pip install keras
pip install matplotlib
pip install pandas
pip install numpy
Run the Application

Upload the Dataset: Click the "Upload NSL KDD Dataset" button to load the dataset (NSL-KDD or any compatible dataset).
Preprocess the Data: Click the "Preprocess Dataset" button to clean the dataset and remove non-numeric values.
Generate the Training Model: Click the "Generate Training Model" button to split the dataset into training and testing sets.
Run SVM or ANN Algorithm: Click either the "Run SVM Algorithm" or "Run ANN Algorithm" button to train and evaluate the models.
Detect Attacks: Upload a test dataset and click the "Upload Test Data & Detect Attack" button to make predictions.
View Accuracy Graph: Click the "Accuracy Graph" button to see a comparison of the accuracies of both models (SVM vs ANN).
Files in the Repository
main.py: The main script containing the entire program.
clean.txt: The cleaned dataset (after preprocessing).
README.md: This file.
