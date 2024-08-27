package httphandler

import (
	"authservice/internal/domain"
	"authservice/internal/service"
	"errors"
	"net/http"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func AdminBlockUser(resp http.ResponseWriter, req *http.Request) {
	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	id := req.URL.Query().Get("user_id")

	userID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	if err := service.BlockUser(&domain.UserBlocker{
		UserId: userID,
	}); err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
		return
	}

}

func AdminChangeRole(resp http.ResponseWriter, req *http.Request) {
	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	id := req.URL.Query().Get("user_id")
	role := req.URL.Query().Get("role")

	userID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	if err := service.ChangeRole(&domain.RoleChanger{
		UserId: userID,
		Role:   role,
	}); err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
		return
	}

}

func AdminChangePassword(resp http.ResponseWriter, req *http.Request) {
	respBody := &HTTPResponse{}

	id := req.URL.Query().Get("user_id")
	password := req.URL.Query().Get("password") //вариант через параметры

	// var input domain.UserPassword

	// if err := readBody(req, &input); err != nil {
	// 	resp.WriteHeader(http.StatusUnprocessableEntity)
	// 	respBody.SetError(err)
	// 	return
	// }

	defer func() {
		// отправить пользоваткелю новый пароль
		resp.Write(respBody.Marshall())
	}()

	userID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	if err := service.ChangePsw(&domain.UserPassword{
		ID:       userID,
		Password: password,
	}); err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
		return
	}

}

func AdminGetUserInfo(resp http.ResponseWriter, req *http.Request) {

	respBody := &HTTPResponse{}
	defer func() {
		resp.Write(respBody.Marshall())
	}()

	id := req.URL.Query().Get("user_id")
	userID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		resp.WriteHeader(http.StatusBadRequest)
		respBody.SetError(errors.New("invalid input"))
		return
	}

	info, err := service.GetUserFullInfo(userID)
	if err != nil {
		resp.WriteHeader(http.StatusNotFound)
		respBody.SetError(err)
	}

	respBody.SetData(info)
}
