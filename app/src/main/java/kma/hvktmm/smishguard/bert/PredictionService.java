package kma.hvktmm.smishguard.bert;

import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;
import retrofit2.Call;
import retrofit2.Response;

public class PredictionService {

    private static final String BASE_URL = "http://192.168.82.3:5000"; // Địa chỉ IP server Flask
    private FlaskApi api;


    public PredictionService() {
        // Tạo Retrofit instance
        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl(BASE_URL)
                .addConverterFactory(GsonConverterFactory.create())
                .build();
        api = retrofit.create(FlaskApi.class);
    }

    // Hàm gửi yêu cầu dự đoán
    public void getPrediction(String msgBody, PredictionCallback callback) {
        // Tạo Retrofit instance
        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl(BASE_URL)
                .addConverterFactory(GsonConverterFactory.create())
                .build();

        FlaskApi api = retrofit.create(FlaskApi.class);

        Call<PredictionResponse> call = api.predict(new PredictionRequest(msgBody));

        call.enqueue(new retrofit2.Callback<PredictionResponse>() {
            @Override
            public void onResponse(Call<PredictionResponse> call, Response<PredictionResponse> response) {
                if (response.body() != null) {
                    callback.onResult(response.body().getPrediction() == 1); // true nếu prediction là 1
                } else {
                    callback.onError("Empty response");
                }
            }

            @Override
            public void onFailure(Call<PredictionResponse> call, Throwable t) {
                callback.onError(t.getMessage());
            }
        });
    }

}
