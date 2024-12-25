package kma.hvktmm.smishguard.bert;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.POST;

public interface FlaskApi {
    @POST("/predict")
    Call<PredictionResponse> predict(@Body PredictionRequest request);
}