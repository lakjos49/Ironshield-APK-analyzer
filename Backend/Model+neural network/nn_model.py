import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt # type: ignore
from sklearn.feature_selection import mutual_info_classif
from skrebate import ReliefF # type: ignore
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score
from tensorflow.keras.models import Sequential # type: ignore
from tensorflow.keras.layers import Dense, Dropout, Input  # type: ignore
from tensorflow.keras.optimizers import Adam # type: ignore
from tensorflow.keras.callbacks import EarlyStopping # type: ignore
DATASET_PATH = "reduced_dataset.csv"
RESULTS_CSV_PATH = "feature_selection_accuracy_results.csv"
RESULTS_TABLE_IMG_PATH = "final_accuracy_table.png"
df = pd.read_csv(DATASET_PATH)
df = df.dropna(subset=["Label"])
for col in df.columns:
    if df[col].dtype == "object":
        df[col] = pd.factorize(df[col])[0]
df["Label"] = df["Label"].replace(
    {"Benign": 0, "benign": 0, "Malware": 1, "malware": 1}
).astype(int)
X = df.drop(columns=["Label"])
y = df["Label"]
feature_list = X.columns.tolist()
X_train_full, X_test_full, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
info_gain_scores = mutual_info_classif(X, y)
info_gain_dict = dict(zip(feature_list, info_gain_scores))
relief = ReliefF(n_neighbors=20)
relief.fit(X.values, y.values)
relief_scores = relief.feature_importances_
relief_dict = dict(zip(feature_list, relief_scores))
corr_scores = df.corr()["Label"].abs().drop("Label")
corr_dict = corr_scores.to_dict()
def rank_dict(d):
    return {k: r for r, k in enumerate(sorted(d, key=d.get, reverse=True), 1)}
r1 = rank_dict(info_gain_dict)
r2 = rank_dict(relief_dict)
r3 = rank_dict(corr_dict)
borda_scores = {f: r1[f] + r2[f] + r3[f] for f in feature_list}
TOP_K = 20
top_info = sorted(info_gain_dict, key=info_gain_dict.get, reverse=True)[:TOP_K]
top_relief = sorted(relief_dict, key=relief_dict.get, reverse=True)[:TOP_K]
top_corr = sorted(corr_dict, key=corr_dict.get, reverse=True)[:TOP_K]
top_borda = sorted(borda_scores, key=borda_scores.get)[:TOP_K]
splits = {
    "No_FS": X_train_full.columns.tolist(),
    "InfoGain": top_info,
    "ReliefF": top_relief,
    "Correlation": top_corr,
    "BordaFusion": top_borda
}
def build_neural_network(input_dim):
    nn = Sequential([
        Input(shape=(input_dim,)),
        Dense(64, activation='relu'),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dropout(0.2),
        Dense(1, activation='sigmoid')
    ])
    nn.compile(optimizer=Adam(learning_rate=0.001),
                 loss='binary_crossentropy', metrics=['accuracy'])
    return nn
classifiers = {
    "RandomForest": RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42),
    "SVM (SGD Hinge)": SGDClassifier(loss="hinge", max_iter=1000, random_state=42),
    "Logistic Regression": SGDClassifier(loss="log_loss", max_iter=1000, random_state=42),
    "GradientBoosting": GradientBoostingClassifier(n_estimators=300, learning_rate=0.05),
}
results = []
for fs_name, cols in splits.items():
    print(f"\n--- Evaluating using feature set: {fs_name} ({len(cols)} features) ---")
    X_train = X_train_full[cols]
    X_test = X_test_full[cols]
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    for clf_name, clf in classifiers.items():
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)
        acc = accuracy_score(y_test, preds)
        results.append([fs_name, clf_name, acc])
        print(f"{clf_name}: {acc:.4f}")
    nn = build_neural_network(input_dim=X_train.shape[1])
    es = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
    nn.fit(X_train_scaled, y_train,
             validation_data=(X_test_scaled, y_test),
             epochs=50, batch_size=32, verbose=0,
             callbacks=[es])
    preds = (nn.predict(X_test_scaled, verbose=0) > 0.5).astype(int)
    acc = accuracy_score(y_test, preds)
    results.append([fs_name, "NeuralNet", acc])
    print(f"NeuralNet: {acc:.4f}")
df_results = pd.DataFrame(results, columns=["Feature_Set", "Model", "Accuracy"])
print("\n\n================ FINAL ACCURACY TABLE ================\n")
print(df_results.to_markdown(index=False, numalign="left", stralign="left", floatfmt=".4f"))
df_results.to_csv(RESULTS_CSV_PATH, index=False)
print(f"\nResults saved to: {RESULTS_CSV_PATH}")
pivot_df = df_results.pivot(index="Model", columns="Feature_Set", values="Accuracy")
plt.figure(figsize=(12, 6))
pivot_df.plot(kind="bar", figsize=(12, 6), ax=plt.gca())
plt.title("Model Accuracy Comparison Across Feature Selection Methods")
plt.ylabel("Accuracy")
plt.xlabel("Models")
plt.xticks(rotation=45)
plt.grid(axis="y", linestyle="--", alpha=0.5)
plt.legend(title="Feature Set", loc="lower right")
plt.tight_layout()
plt.savefig("Bar_Chart_Accuracy_Comparison.png")
plt.close()
plt.figure(figsize=(12, 6))
for model in pivot_df.index:
    plt.plot(pivot_df.columns, pivot_df.loc[model], marker='o', label=model)
plt.title("Accuracy Trend for Each Model Across Feature Selection Techniques")
plt.ylabel("Accuracy")
plt.xlabel("Feature Selection Method")
plt.grid(True, linestyle="--", alpha=0.5)
plt.legend()
plt.tight_layout()
plt.savefig("Line_Graph_Accuracy_Trend.png")
plt.close()
plt.figure(figsize=(10, 5))
plt.imshow(pivot_df, cmap="viridis", aspect="auto")
plt.colorbar(label="Accuracy")
plt.title("Heatmap of Accuracy Values (Models vs Feature Selection)")
plt.xticks(ticks=range(len(pivot_df.columns)), labels=pivot_df.columns, rotation=45)
plt.yticks(ticks=range(len(pivot_df.index)), labels=pivot_df.index)
plt.tight_layout()
plt.savefig("Heatmap_Accuracy_Values.png")
plt.close()
fig, ax = plt.subplots(figsize=(10, 4))
ax.axis('tight')
ax.axis('off')
table = ax.table(
    cellText=np.round(df_results.values, 4),
    colLabels=df_results.columns,
    cellLoc='center',
    loc='center'
)
table.auto_set_font_size(False)
table.set_fontsize(10)
table.scale(1.2, 1.2)
plt.savefig(RESULTS_TABLE_IMG_PATH, bbox_inches='tight', dpi=300)
plt.close()
print(f"Table image saved at: {RESULTS_TABLE_IMG_PATH}")
print("\nGenerated plots (Bar_Chart_Accuracy_Comparison.png, Line_Graph_Accuracy_Trend.png, Heatmap_Accuracy_Values.png) saved in the script directory.")