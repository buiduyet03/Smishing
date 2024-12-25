package kma.hvktmm.smishguard.bert;
public class PredictionRequest {
    private String text;

    public PredictionRequest(String text) {
        this.text = text;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }
}
