package kma.hvktmm.smishguard.bert;

public interface PredictionCallback {
    void onResult(boolean isMalicious);

    void onError(String error);
}
