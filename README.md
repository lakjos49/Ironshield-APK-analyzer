# Ironshield-APK-analyzer

# ** Android APK Malware Analyzer**

A complete **static analysis and machine-learning–powered APK classification system** built using Flask, Scikit-Learn, TensorFlow, and multi-layer permission extraction pipelines.
This tool automatically extracts permissions from APK files, performs feature engineering, applies multiple ML models, evaluates risk, visualizes results, and generates a full **PDF malware analysis report**.

---

## ** Summary**

The APK Malware Analyzer is a web-based system that inspects Android applications for malicious behavior using static analysis and machine learning.
It extracts explicit and implicit permissions, builds feature vectors, analyzes app legitimacy based on permission use, and classifies APKs using five machine-learning models (Random Forest, SVM, Logistic Regression, Gradient Boosting, and a Neural Network).

Additionally, the system performs **feature ranking** using Information Gain, Relief-F, and Correlation scores, merges them using Borda count, and provides detailed visual insights.
The analyzer also generates a **professional PDF report** containing risk scores, charts, permission breakdowns, and top risky permissions.

---

## ** Key Features**

### ** 1. Multi-Layer Permission Extraction**

Supports multiple fallbacks:

* apkutils2 manifest parser
* Androguard APK inspector
* Regex-based permission extraction
* AXMLPrinter2 for binary manifest decoding

Extracts:

* Explicit permissions
* Implicit permissions (inferred from app behavior)

---

### ** 2. Machine Learning–Based Malware Classification**

Uses 5 classification models:

* Random Forest
* Support Vector Machine
* Logistic Regression
* Gradient Boosting
* Neural Network (Keras/TensorFlow)

Combines model outputs to compute:

* **Average threat probability**
* **Final malware verdict**

---

### ** 3. Feature Ranking & Explainability**

Computes importance scores using:

* Information Gain
* Relief-F
* Correlation with class label

Uses **Borda Count Fusion** to generate a unified ranking.

Graphs auto-generated:

* Feature ranking bars
* Permission distribution pie chart
* Risk meter
* Model confidence bars

---

### ** 4. APK Type Identification & Permission Legitimacy**

Automatically identifies app category (e.g., Social Media, Navigation, Finance).
Checks whether requested permissions are:

* Legitimate
* Excessive
* Unusual for the app category

---

### ** 5. PDF Report Generation**

The system generates a complete **malware analysis PDF report** including:

* Verdict (Benign, Malicious, Greyware, Permission-heavy, etc.)
* Threat score
* Top 5 risky permissions
* Model score charts
* Permission distribution
* Risk meter
* Feature selection visualizations

---

### ** 6. Flask Web Interface**

Simple web-based interface with:

* APK upload
* JSON API endpoint
* Report download button

---

## ** Requirements**

### **Python Version**

```
Python 3.8+
```

### **Required Libraries**

Install dependencies using:

```bash
pip install -r requirements.txt
```

### **Main Dependencies List**

```
Flask
pandas
numpy
joblib
tensorflow
scikit-learn
matplotlib
apkutils2
androguard
skrebate
reportlab
```

### **System Requirements**

* **Java** (for AXMLPrinter2)
* Able to run Flask web server
* CPU recommended (GPU optional for TensorFlow model)

---

## ** Running the Application**

```bash
python app.py
```

Then open:

```
http://localhost:5000
```

Upload an APK → View analysis → Download PDF report.

---

## ** Output Includes**

* Permission breakdown (explicit, implicit, excessive)
* App type classification
* ML model confidence scores
* Threat/risk score
* Risky permissions list
* Explanation charts
* Final verdict (Benign / Malicious / Greyware)

