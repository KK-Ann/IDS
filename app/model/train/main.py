import pandas as pd
import numpy as np
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
import joblib
import pickle
import warnings
from collections import Counter
warnings.filterwarnings('ignore')


# ====================== 1. 数据加载与预处理 ======================
def load_and_preprocess(filepath):
    data = pd.read_csv(filepath)
    data.columns = data.columns.str.strip()
    print("列名：", data.columns.tolist())


    data = data.drop(['Flow ID', 'Source IP', 'Destination IP', 'Timestamp','Fwd Header Length.1'], axis=1, errors='ignore')
    data = data.dropna()

    # if 'Label' not in data.columns:
    #     raise KeyError("列 'Label' 不存在，请检查文件列名")
    # ========== 打乱并随机减少20% ==========
    data = data.sample(frac=1, random_state=42).reset_index(drop=True)  # 打乱顺序
    # reduced_size = int(len(data) * 0.8)  # 保留80%
    # data = data.iloc[:reduced_size]  # 截取前80%
    le_dict = {}
    for col in ['Label']:
        le = LabelEncoder()
        data[col] = le.fit_transform(data[col])
        le_dict[col] = le

    X = data.drop('Label', axis=1)
    y = data['Label']
    print("各类别样本数量：", Counter(y))
    return X, y, le_dict


# ====================== 2. 特征工程 ======================
def feature_engineering(X, y):
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 设置类别0保留30000样本，其他不变
    rus = RandomUnderSampler(sampling_strategy={0: 50000}, random_state=42)
    X_under, y_under = rus.fit_resample(X_scaled, y)
    print("欠采样后类别分布：", Counter(y_under))



    # 最后降维
    pca = PCA(n_components=0.95)
    X_pca = pca.fit_transform(X_under)

    return X_pca.astype(np.float32), y_under, scaler, pca


# ====================== 3. 滑动窗口生成器 ======================
def sliding_window_generator(X, y, window_size=100, batch_size=512):
    total_samples = len(X) - window_size
    for start in range(0, total_samples, batch_size):
        end = min(start + batch_size, total_samples)
        X_batch = [X[i:i+window_size] for i in range(start, end)]
        y_batch = [y[i+window_size] for i in range(start, end)]
        yield np.array(X_batch, dtype=np.float32), np.array(y_batch)


# ====================== 4. 模型构建 ======================
def build_model():
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [None, 10],
        'min_samples_split': [2, 5],
        'class_weight': ['balanced', None]
    }

    model = GridSearchCV(
        estimator=RandomForestClassifier(random_state=42),
        param_grid=param_grid,
        cv=3,
        n_jobs=-1,
        scoring='f1_macro'
    )
    return model


# ====================== 主流程 ======================
if __name__ == "__main__":
    # Step 1: 加载原始数据
    X, y, label_encoders = load_and_preprocess("./data/TrafficLabelling/merged_data.csv")

    # Step 2: 划分原始数据（确保 stratify）
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print("训练集标签分布：", Counter(y_train))
    print("测试集标签分布：", Counter(y_test))
    #  修复索引
    X_train = X_train.reset_index(drop=True)
    X_test = X_test.reset_index(drop=True)
    y_train = y_train.reset_index(drop=True)
    y_test = y_test.reset_index(drop=True)
    # Step 3: 对训练集进行标准化 + PCA + 欠采样 + SMOTE
    X_train_proc, y_train_proc, scaler, pca = feature_engineering(X_train, y_train)

    # Step 4: 对测试集仅做标准化和 PCA（不要做 SMOTE）
    X_test_scaled = scaler.transform(X_test)
    X_test_pca = pca.transform(X_test_scaled)

    # Step 5: 训练模型
    model = build_model()
    model.fit(X_train_proc, y_train_proc)

    # Step 7: 预测与评估
    y_pred = model.predict(X_test_pca)

    print("\n最佳参数:", model.best_params_)
    print(classification_report(y_test, y_pred))

    # Step 8: 模型与预处理保存
    joblib.dump(model.best_estimator_, 'optimized_rf_model.pkl')

    with open('preprocessing_pipeline.pkl', 'wb') as f:
        pickle.dump({
            'scaler': scaler,
            'pca': pca,
            'label_encoder': label_encoders['Label']
        }, f)

