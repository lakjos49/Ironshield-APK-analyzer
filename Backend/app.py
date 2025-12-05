
from flask import Flask, render_template, request, jsonify # type: ignore
import os
import tempfile
import pandas as pd
import joblib
from zipfile import ZipFile
from tensorflow.keras.models import load_model # type: ignore
from sklearn.preprocessing import StandardScaler
import re
import matplotlib # type: ignore
matplotlib.use("Agg")
import matplotlib.pyplot as plt # type: ignore
import io
import base64
from sklearn.feature_selection import mutual_info_classif
from skrebate import ReliefF # type: ignore
import numpy as np
from flask import send_file # type: ignore
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer # type: ignore
from reportlab.lib.pagesizes import A4 # type: ignore
from reportlab.lib.styles import getSampleStyleSheet # type: ignore
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle # type: ignore
from reportlab.lib import colors # type: ignore
from reportlab.lib.pagesizes import A4 # type: ignore
from reportlab.lib.styles import getSampleStyleSheet # type: ignore
from reportlab.lib.units import inch # type: ignore

app = Flask(__name__, template_folder="templates", static_folder="static")
UPLOAD_FOLDER = os.path.join(app.static_folder, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# CONFIG

DATASET_PATH = r"C:\Users\hp\Downloads\MAJOR PROJECT-1\dataset\reduced_dataset.csv"

MODEL_PATHS = {
    "RandomForest": r"C:\Users\hp\Downloads\MAJOR PROJECT-1\model1\rf.pkl",
    "SVM": r"C:\Users\hp\Downloads\MAJOR PROJECT-1\model1\svm.pkl",
    "LogisticRegression": r"C:\Users\hp\Downloads\MAJOR PROJECT-1\model1\log.pkl",
    "GradientBoosting": r"C:\Users\hp\Downloads\MAJOR PROJECT-1\model1\gb.pkl",
    "NeuralNet": r"C:\Users\hp\Downloads\MAJOR PROJECT-1\model1\neural_net_model.h5"
}


# LOAD DATASET

df = pd.read_csv(DATASET_PATH).dropna(subset=["Label"])


for col in df.columns:
    if df[col].dtype == "object":
        df[col] = pd.factorize(df[col])[0]

df["Label"] = df["Label"].replace({
    "Benign": 1, "Malicious": 0, "malware": 0, "benign": 1
}).astype(int)

X = df.drop(columns=["Label"])
y = df["Label"]
feature_list = list(X.columns)




#  Information Gain
info_gain_scores = mutual_info_classif(X, y)
info_gain_dict = dict(zip(feature_list, info_gain_scores))

#  Relief-F
relief = ReliefF(n_neighbors=20)
relief.fit(X.values, y.values)
relief_scores = relief.feature_importances_
relief_dict = dict(zip(feature_list, relief_scores))

#  Correlation
corr_scores = df.corr()["Label"].abs().drop("Label")
corr_dict = corr_scores.to_dict()

#  Borda Count Fusion
def rank_dict(d):
    return {k: r for r, k in enumerate(sorted(d, key=d.get, reverse=True), 1)}

r1 = rank_dict(info_gain_dict)
r2 = rank_dict(relief_dict)
r3 = rank_dict(corr_dict)

borda_scores = {f: r1[f] + r2[f] + r3[f] for f in feature_list}


# FEATURE RANKING GRAPH MAKER

def plot_feature_ranking(score_dict, title):
    items = sorted(score_dict.items(), key=lambda x: x[1], reverse=True)[:15]
    labels = [i[0] for i in items]
    values = [i[1] for i in items]

    plt.figure(figsize=(6, 4))
    plt.barh(labels, values, color="cyan")
    plt.gca().invert_yaxis()
    plt.title(title)
    plt.tight_layout()
    return fig_to_base64()


rf = joblib.load(MODEL_PATHS["RandomForest"])
svm_lr = joblib.load(MODEL_PATHS["SVM"])
log_lr = joblib.load(MODEL_PATHS["LogisticRegression"])
gb = joblib.load(MODEL_PATHS["GradientBoosting"])
nn = load_model(MODEL_PATHS["NeuralNet"])

models = {
    "RandomForest": rf,
    "SVM": svm_lr,
    "LogisticRegression": log_lr,
    "GradientBoosting": gb,
    "NeuralNet": nn
}


scaler = StandardScaler().fit(X)



def extract_permissions(apk_path):
    import tempfile
    import subprocess
    import xml.etree.ElementTree as ET
    from zipfile import ZipFile
    from apkutils2 import APK as APKUTILS # type: ignore
    import re
    import os

    explicit = set()
    implicit = set()
    apk_to_parse = apk_path

    try:
        with ZipFile(apk_path, 'r') as z:
            if "base.apk" in z.namelist():
                temp_base = tempfile.NamedTemporaryFile(delete=False, suffix=".apk")
                temp_base.write(z.read("base.apk"))
                temp_base.close()
                apk_to_parse = temp_base.name
    except:
        pass

    try:
        apk = APKUTILS(apk_to_parse)
        m = apk.get_manifest()

        if "uses-permission" in m:
            for perm in m["uses-permission"]:
                p = perm.get("@android:name") or perm.get("@name")
                if p:
                    explicit.add(p)

        if len(explicit) > 0:
            text = str(m).lower()
            if "camera" in text: implicit.add("android.permission.CAMERA")
            if "location" in text: implicit.add("android.permission.ACCESS_FINE_LOCATION")
            if "microphone" in text or "audio" in text: implicit.add("android.permission.RECORD_AUDIO")
            if "bluetooth" in text: implicit.add("android.permission.BLUETOOTH")

            return sorted(explicit | implicit), sorted(explicit), sorted(implicit)
    except:
        pass

    try:
        from androguard.core.bytecodes.apk import APK as ANDRO # type: ignore
        a = ANDRO(apk_to_parse)
        exp = a.get_permissions()

        if exp:
            explicit.update(exp)
            feats = " ".join(str(f).lower() for f in a.get_features() or [])
            if "camera" in feats: implicit.add("android.permission.CAMERA")
            if "location" in feats: implicit.add("android.permission.ACCESS_FINE_LOCATION")
            if "microphone" in feats or "audio" in feats: implicit.add("android.permission.RECORD_AUDIO")
            if "bluetooth" in feats: implicit.add("android.permission.BLUETOOTH")

            return sorted(explicit | implicit), sorted(explicit), sorted(implicit)
    except:
        pass

    try:
        PERM_REGEX = re.compile(r'android\.permission\.[A-Z0-9_]+', re.IGNORECASE)

        with ZipFile(apk_to_parse, 'r') as z:
            for name in z.namelist():
                if 'AndroidManifest.xml' in name:
                    raw = z.read(name)
                    try:
                        txt = raw.decode("utf-8", errors="ignore")
                    except:
                        txt = str(raw)

                    perms = PERM_REGEX.findall(txt)
                    explicit.update(perms)
                    break

        if len(explicit) > 0:
            return sorted(explicit | implicit), sorted(explicit), sorted(implicit)
    except:
        pass

    try:
        temp_axml = tempfile.NamedTemporaryFile(delete=False)
        temp_xml = tempfile.NamedTemporaryFile(delete=False)

        with ZipFile(apk_to_parse, 'r') as z:
            temp_axml.write(z.read("AndroidManifest.xml"))
        temp_axml.close()
        temp_xml.close()

        cmd = f'java -jar AXMLPrinter2.jar "{temp_axml.name}" > "{temp_xml.name}"'
        subprocess.run(cmd, shell=True)

        tree = ET.parse(temp_xml.name)
        root = tree.getroot()

        for item in root.iter():
            for k, v in item.attrib.items():
                if "permission" in v.lower():
                    explicit.add(v)
    except:
        pass
    explicit = {p.replace("android.permission.", "") for p in explicit}
    implicit = {p.replace("android.permission.", "") for p in implicit}

    return sorted(explicit | implicit), sorted(explicit), sorted(implicit)


#  FEATURE VECTOR

def build_feature_vector(perms):
    # Normalize only android.permission.* formats
    normalized = set()

    for p in perms:
        p = p.replace("android.permission.", "")
        normalized.add(p)  
    vec = {f: (1 if f in normalized else 0) for f in feature_list}

    return pd.DataFrame([vec])



# PERMISSIONS


APP_TYPE_PERMISSIONS = {
    "Camera": ["CAMERA","RECORD_AUDIO","ACCESS_MEDIA_LOCATION","WRITE_EXTERNAL_STORAGE","READ_EXTERNAL_STORAGE","FOREGROUND_SERVICE","ACCESS_NETWORK_STATE","INTERNET","POST_NOTIFICATIONS","VIBRATE"],
    "SocialMedia": [
    "INTERNET","ACCESS_NETWORK_STATE","ACCESS_WIFI_STATE","ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION",
    "CAMERA","RECORD_AUDIO","READ_CONTACTS","WRITE_CONTACTS","READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_AUDIO","READ_MEDIA_IMAGES","READ_MEDIA_VIDEO","POST_NOTIFICATIONS","VIBRATE","WAKE_LOCK",
    "FOREGROUND_SERVICE","FOREGROUND_SERVICE_CAMERA","FOREGROUND_SERVICE_MICROPHONE","FOREGROUND_SERVICE_LOCATION",
    "FOREGROUND_SERVICE_DATA_SYNC","GET_ACCOUNTS","AUTHENTICATE_ACCOUNTS","USE_CREDENTIALS","MANAGE_ACCOUNTS",
    "READ_PHONE_STATE","READ_PHONE_NUMBERS","READ_PROFILE","SEND_SMS","RECEIVE_SMS","NFC","BLUETOOTH",
    "BLUETOOTH_CONNECT","BLUETOOTH_SCAN","CHANGE_WIFI_STATE","CHANGE_NETWORK_STATE","RECEIVE_BOOT_COMPLETED",
    "AD_ID","REQUEST_INSTALL_PACKAGES","INSTALL_SHORTCUT","UNINSTALL_SHORTCUT",
    "DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION","BIND_GET_INSTALL_REFERRER_SERVICE"
    ],

    "Messaging": ["INTERNET","ACCESS_NETWORK_STATE","READ_CONTACTS","SEND_SMS","RECEIVE_SMS","RECEIVE_MMS","READ_SMS","WRITE_EXTERNAL_STORAGE","READ_EXTERNAL_STORAGE","VIBRATE","POST_NOTIFICATIONS","FOREGROUND_SERVICE","WAKE_LOCK"],
    "Navigation": ["ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION","ACCESS_BACKGROUND_LOCATION","INTERNET","ACCESS_NETWORK_STATE","WAKE_LOCK","VIBRATE","FOREGROUND_SERVICE","ACCESS_WIFI_STATE","CHANGE_WIFI_STATE","BLUETOOTH","BLUETOOTH_CONNECT","BLUETOOTH_SCAN"],
    "Finance": ["INTERNET","ACCESS_NETWORK_STATE","USE_BIOMETRIC","USE_FINGERPRINT","RECEIVE_BOOT_COMPLETED","REQUEST_IGNORE_BATTERY_OPTIMIZATIONS","WAKE_LOCK","WRITE_EXTERNAL_STORAGE","READ_EXTERNAL_STORAGE","POST_NOTIFICATIONS","FOREGROUND_SERVICE","RECEIVE","BIND_GET_INSTALL_REFERRER_SERVICE"],

    "Shopping": ["INTERNET","ACCESS_NETWORK_STATE","ACCESS_WIFI_STATE","GET_ACCOUNTS","AUTHENTICATE_ACCOUNTS","USE_CREDENTIALS","MANAGE_ACCOUNTS","POST_NOTIFICATIONS","READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE","MANAGE_EXTERNAL_STORAGE","FOREGROUND_SERVICE","ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION","CAMERA","RECORD_AUDIO","REQUEST_INSTALL_PACKAGES","REQUEST_DELETE_PACKAGES","DELETE_PACKAGES","RECEIVE_BOOT_COMPLETED","WAKE_LOCK",
                 "AD_ID","COM.GOOGLE.ANDROID.C2DM.PERMISSION.RECEIVE","BIND_GET_INSTALL_REFERRER_SERVICE","QUERY_ALL_PACKAGES","PACKAGE_USAGE_STATS","INSTALL_PACKAGES","GET_PACKAGE_SIZE"],

    "HealthFitness": ["INTERNET","ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION","BODY_SENSORS","ACTIVITY_RECOGNITION","FOREGROUND_SERVICE","VIBRATE","POST_NOTIFICATIONS","BLUETOOTH_CONNECT","WAKE_LOCK"],
    "Game":["INTERNET","ACCESS_NETWORK_STATE","ACCESS_WIFI_STATE","CHANGE_WIFI_STATE","READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE","VIBRATE","WAKE_LOCK","FOREGROUND_SERVICE","BILLING","COM.ANDROID.VENDING.BILLING","C2D_MESSAGE","RECEIVE","REGISTRATION","COM.GOOGLE.ANDROID.C2DM.PERMISSION.RECEIVE","BIND_GET_INSTALL_REFERRER_SERVICE","GET_ACCOUNTS","ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION","POST_NOTIFICATIONS"],

    "Utility": ["INTERNET","ACCESS_NETWORK_STATE","WRITE_EXTERNAL_STORAGE","READ_EXTERNAL_STORAGE","REQUEST_INSTALL_PACKAGES","FOREGROUND_SERVICE","RECEIVE_BOOT_COMPLETED","WAKE_LOCK","POST_NOTIFICATIONS","ACCESS_WIFI_STATE"],
    "MusicAudio": [ "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "NEARBY_WIFI_DEVICES", "BLUETOOTH", "BLUETOOTH_ADMIN", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN", "BLUETOOTH_ADVERTISE", "RECORD_AUDIO", "READ_MEDIA_AUDIO", "MODIFY_AUDIO_SETTINGS", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "FOREGROUND_SERVICE", "FOREGROUND_SERVICE_MEDIA_PLAYBACK", "FOREGROUND_SERVICE_DATA_SYNC", "FOREGROUND_SERVICE_CONNECTED_DEVICE", "POST_NOTIFICATIONS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "WAKE_LOCK", "VIBRATE", "RECEIVE_BOOT_COMPLETED", "GET_ACCOUNTS", "USE_CREDENTIALS", "BILLING", "COM.ANDROID.VENDING.BILLING", "AD_ID", "C2D_MESSAGE", "COM.GOOGLE.ANDROID.C2DM.PERMISSION.RECEIVE", "BIND_GET_INSTALL_REFERRER_SERVICE", "READ_PHONE_STATE", "READ_GSERVICES", "NFC" ],
    "VideoStreaming": [
    "INTERNET","ACCESS_NETWORK_STATE","ACCESS_WIFI_STATE","READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE",
    "ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION","BLUETOOTH","RECORD_AUDIO","CAMERA",
    "POST_NOTIFICATIONS","WAKE_LOCK","VIBRATE","FOREGROUND_SERVICE","FOREGROUND_SERVICE_MEDIA_PLAYBACK",
    "FOREGROUND_SERVICE_DATA_SYNC","RECEIVE_BOOT_COMPLETED","REQUEST_INSTALL_PACKAGES","REQUEST_DELETE_PACKAGES",
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS","SYSTEM_ALERT_WINDOW","ACCESS_ALL_DOWNLOADS","AD_ID",
    "ACCESS_ADSERVICES_AD_ID","ACCESS_ADSERVICES_ATTRIBUTION","ACCESS_ADSERVICES_TOPICS",
    "COM.GOOGLE.ANDROID.C2DM.PERMISSION.RECEIVE","BIND_GET_INSTALL_REFERRER_SERVICE","INSTALL_SHORTCUT",
    "DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
],

    "Productivity": ["INTERNET","ACCESS_NETWORK_STATE","READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE","CAMERA","RECORD_AUDIO","READ_CALENDAR","WRITE_CALENDAR","POST_NOTIFICATIONS","FOREGROUND_SERVICE","WAKE_LOCK","VIBRATE"],
    "SmartHome": ["INTERNET","ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION","BLUETOOTH","BLUETOOTH_ADMIN","BLUETOOTH_CONNECT","BLUETOOTH_SCAN","ACCESS_WIFI_STATE","CHANGE_WIFI_STATE","CAMERA","RECORD_AUDIO","FOREGROUND_SERVICE","WAKE_LOCK","POST_NOTIFICATIONS"],
    "SystemAdmin": ["INTERNET","ACCESS_NETWORK_STATE","RECEIVE_BOOT_COMPLETED","WAKE_LOCK","REQUEST_DELETE_PACKAGES","PACKAGE_USAGE_STATS","WRITE_SETTINGS","SYSTEM_ALERT_WINDOW","POST_NOTIFICATIONS"],
    "Travel": ["INTERNET","ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION","ACCESS_BACKGROUND_LOCATION","POST_NOTIFICATIONS","ACCESS_NETWORK_STATE","WAKE_LOCK","VIBRATE","FOREGROUND_SERVICE"],
    "FoodDelivery": ["INTERNET","ACCESS_NETWORK_STATE","ACCESS_WIFI_STATE","ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION","CAMERA","POST_NOTIFICATIONS","WAKE_LOCK","FOREGROUND_SERVICE","GET_ACCOUNTS","AUTHENTICATE_ACCOUNTS","USE_CREDENTIALS","MANAGE_ACCOUNTS","READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE","REQUEST_INSTALL_PACKAGES","REQUEST_DELETE_PACKAGES","INSTALL_PACKAGES","RECEIVE_BOOT_COMPLETED","QUERY_ALL_PACKAGES","CHANGE_WIFI_MULTICAST_STATE","READ_SYNC_SETTINGS","READ_SYNC_STATS","WRITE_SYNC_SETTINGS","COM.GOOGLE.ANDROID.C2DM.PERMISSION.RECEIVE","BIND_GET_INSTALL_REFERRER_SERVICE","AD_ID","INSTALL_SHORTCUT"],

}

def classify_app_type(permissions):
    short = {p.split(".")[-1].upper() for p in permissions}
    best_type, best_score = "Unknown", 0
    for cat, perms in APP_TYPE_PERMISSIONS.items():
        score = len(short.intersection(perms))
        if score > best_score:
            best_type, best_score = cat, score
    return best_type

def analyze_permission_legitimacy(app_type, permissions):
    short = {p.split(".")[-1].upper() for p in permissions}
    allowed = set(APP_TYPE_PERMISSIONS.get(app_type, []))
    excessive = list(short - allowed)
    return {
        "AppType": app_type,
        "ExcessivePermissions": excessive,
        "LegitUsage": len(excessive) == 0
    }


def fig_to_base64():
    buf = io.BytesIO()
    plt.savefig(buf, format="png", dpi=120, bbox_inches="tight")
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


#  APK CLASSIFICATION

def classify_apk(apk_path):
    
    # PERMISSION EXTRACTION
    
    permissions, explicit_p, implicit_p = extract_permissions(apk_path)

    app_type = classify_app_type(permissions)
    legit = analyze_permission_legitimacy(app_type, permissions)

    X_test = build_feature_vector(permissions)
    model_scores = {}

    
    # MODEL PREDICTIONS
    
    for name, model in models.items():
        df_model = X_test.reindex(columns=feature_list, fill_value=0)
        try:
            if name == "NeuralNet":
                proba = float(
                    model.predict(scaler.transform(df_model), verbose=0)[0][0]
                )
            elif hasattr(model, "predict_proba"):
                proba = model.predict_proba(df_model)[0][1]
            else:
                proba = float(model.predict(df_model)[0])
        except:
            proba = 0.0

        model_scores[name] = round(float(proba), 4)

    avg_score = sum(model_scores.values()) / len(model_scores)

    
    danger_scores = {}

    for perm in permissions:
        short = perm


        ig = info_gain_dict.get(short, 0)
        rf = relief_dict.get(short, 0)
        co = corr_dict.get(short, 0)

        danger_scores[short] = ig * 0.5 + rf * 0.3 + co * 0.2

    top5_risky = sorted(
        danger_scores.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    
    # DATA VISUALIZATIONS
    
    plt.figure(figsize=(6, 3))
    plt.bar(model_scores.keys(), model_scores.values(), color="cyan")
    plt.title("Model Confidence Scores")
    plt.ylabel("Probability")
    plt.xticks(rotation=30)
    model_scores_img = fig_to_base64()

    
    labels = ["Explicit", "Implicit", "Excessive"]
    sizes = [
        len(explicit_p),
        len(implicit_p),
        len(legit["ExcessivePermissions"])
    ]

    plt.figure(figsize=(4, 4))
    plt.pie(
        sizes,
        labels=labels,
        autopct="%1.1f%%",
        colors=["#00ffff", "#ffaa00", "#ff4444"]
    )
    plt.title("Permission Distribution")
    permissions_pie_img = fig_to_base64()

    
    fig, ax = plt.subplots(figsize=(5, 1.5))
    ax.barh(
        [0], [avg_score],
        color="red" if avg_score > 0.7 else
              "orange" if avg_score > 0.4 else
              "green"
    )
    ax.set_xlim(0, 1)
    ax.set_title("Risk Meter")
    ax.set_yticks([])
    risk_meter_img = fig_to_base64()

    
    info_gain_graph = plot_feature_ranking(info_gain_dict, "Info Gain Ranking")
    relief_graph = plot_feature_ranking(relief_dict, "ReliefF Ranking")
    borda_graph = plot_feature_ranking(borda_scores, "Borda Count Ranking")

    
    # VERDICT LOGIC
    
    LOW, MID = 0.4, 0.7
    TRUSTED = [
        "whatsapp", "instagram", "facebook",
        "telegram", "snapchat", "google", "youtube"
    ]
    apk_lower = os.path.basename(apk_path).lower()

    if legit["LegitUsage"] and avg_score < LOW:
        verdict, label = "Benign", "safe"
    elif any(t in apk_lower for t in TRUSTED) and avg_score < MID:
        verdict, label = "Benign", "safe"
    elif legit["LegitUsage"] and avg_score >= LOW:
        verdict, label = "Benign but Permission-Heavy", "safe"
    elif not legit["LegitUsage"] and avg_score < LOW:
        verdict, label = "Benign but Over-Permissioned [manually check permissions]", "safe"
    elif avg_score < MID:
        verdict, label = "Greyware:Potentially Unwanted", "dangerous"
    else:
        verdict, label = "Malicious", "dangerous"

    
    # JSON
   
    return {
        "permissions": permissions,
        "explicit_permissions": explicit_p,
        "implicit_permissions": implicit_p,
        "app_type": app_type,
        
        "excessive_permissions": legit["ExcessivePermissions"],

        "model_scores": model_scores,
        "average_score": round(avg_score, 3),
        "threat_score": round(avg_score, 3),  

        "verdict": verdict,
        "label": label,

        "charts": {
            "model_scores": model_scores_img,
            "permission_pie": permissions_pie_img,
            "risk_meter": risk_meter_img
        },

        "feature_selection": {
            "info_gain": info_gain_graph,
            "relief_f": relief_graph,
            "borda_count": borda_graph
        },

        "top_risky_permissions": top5_risky
    }



# ROUTES

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("apkFile")
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)

    try:
        result = classify_apk(path)
        os.remove(path)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/download_report", methods=["POST"])
def download_report():
    try:
        data = request.json  
        if not data:
            return "No data provided", 400

        pdf_path = os.path.join(tempfile.gettempdir(), "apk_analysis_report.pdf")

        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(pdf_path, pagesize=A4)
        story = []

        
        story.append(Paragraph("<b>Android Malware Analysis Report</b>", styles["Title"]))
        story.append(Spacer(1, 12))

        
        story.append(Paragraph(f"<b>Verdict:</b> {data['verdict']}", styles["Normal"]))
        story.append(Paragraph(f"<b>Label:</b> {data['label']}", styles["Normal"]))
        story.append(Paragraph(f"<b>Threat Score:</b> {round(data['threat_score'],3)}", styles["Normal"]))
        story.append(Spacer(1, 16))

        
        story.append(Paragraph("<b>Top 5 Risky Permissions</b>", styles["Heading2"]))

        risky = data.get("top_risky_permissions", [])
        if risky:
            table_data = [["Permission", "Score"]]
            for perm, score in risky:
                table_data.append([perm, round(score, 3)])

            table = Table(table_data, colWidths=[3*inch, 1.5*inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), colors.cyan),
                ("TEXTCOLOR", (0,0), (-1,0), colors.black),
                ("BACKGROUND", (0,1), (-1,-1), colors.darkgray),
                ("TEXTCOLOR", (0,1), (-1,-1), colors.white),
                ("GRID", (0,0), (-1,-1), 1, colors.white),
                ("FONTNAME", (0,0), (-1,-1), "Helvetica-Bold"),
            ]))
            story.append(table)
        else:
            story.append(Paragraph("No risky permissions detected.", styles["Normal"]))

        story.append(Spacer(1, 20))

   
        def decode_and_save(base64_str, filename):
            img_path = os.path.join(tempfile.gettempdir(), filename)
            with open(img_path, "wb") as f:
                f.write(base64.b64decode(base64_str))
            return img_path

        # Model scores chart
        if "charts" in data:
            model_chart_path = decode_and_save(data["charts"]["model_scores"], "model_chart.png")
            story.append(Paragraph("<b>Model Confidence Scores</b>", styles["Heading2"]))
            story.append(Image(model_chart_path, width=400, height=250))
            story.append(Spacer(1, 20))

            pie_chart_path = decode_and_save(data["charts"]["permission_pie"], "pie_chart.png")
            story.append(Paragraph("<b>Permission Distribution</b>", styles["Heading2"]))
            story.append(Image(pie_chart_path, width=350, height=250))
            story.append(Spacer(1, 20))

            risk_chart_path = decode_and_save(data["charts"]["risk_meter"], "risk_chart.png")
            story.append(Paragraph("<b>Risk Meter</b>", styles["Heading2"]))
            story.append(Image(risk_chart_path, width=400, height=120))
            story.append(Spacer(1, 20))

        # Feature Selection Charts
        if "feature_selection" in data:
            fs = data["feature_selection"]

            info_path = decode_and_save(fs["info_gain"], "info_gain.png")
            story.append(Paragraph("<b>Info Gain Ranking</b>", styles["Heading2"]))
            story.append(Image(info_path, width=400, height=300))
            story.append(Spacer(1, 20))

            rf_path = decode_and_save(fs["relief_f"], "relief_f.png")
            story.append(Paragraph("<b>ReliefF Ranking</b>", styles["Heading2"]))
            story.append(Image(rf_path, width=400, height=300))
            story.append(Spacer(1, 20))

            borda_path = decode_and_save(fs["borda_count"], "borda.png")
            story.append(Paragraph("<b>Borda Count Ranking</b>", styles["Heading2"]))
            story.append(Image(borda_path, width=400, height=300))
            story.append(Spacer(1, 20))

        # Build PDF
        doc.build(story)

        return send_file(
            pdf_path,
            as_attachment=True,
            download_name="apk_analysis_report.pdf",
            mimetype="application/pdf"
        )

    except Exception as e:
        return str(e), 500


if __name__ == "__main__":
    app.run(debug=True)
