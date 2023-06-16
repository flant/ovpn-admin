package backend

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func (oAdmin *OvpnAdmin) UserListHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	if *StorageBackend == "kubernetes.secrets" {
		err := oAdmin.KubeClient.updateIndexTxtOnDisk()
		if err != nil {
			log.Errorln(err)
		}
		oAdmin.clients = oAdmin.usersList()
	}
	
	usersList, _ := json.Marshal(oAdmin.clients)
	fmt.Fprintf(w, "%s", usersList)
}

func (oAdmin *OvpnAdmin) AuthCheckHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	_ = r.ParseForm()
	authErr := oAdmin.checkAuth(r.FormValue("username"), r.FormValue("token"))
	if authErr != nil {
		http.Error(w, "auth failed", http.StatusUnauthorized)
	}

	fmt.Fprint(w, "auth ok")

}

func (oAdmin *OvpnAdmin) UserGetSecretHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.OnlyMasterWrapper(w, r, false)
	_ = r.ParseForm()

	userSecret, err := oAdmin.getUserSecret(r.FormValue("username"))

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, userSecret)
	}

}

func (oAdmin *OvpnAdmin) UserSetupTFAHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.OnlyMasterWrapper(w, r, false)
	_ = r.ParseForm()

	err := oAdmin.registerUserAuthApp(r.FormValue("username"), r.FormValue("token"))

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Application registered")
	}
}

func (oAdmin *OvpnAdmin) UserResetTFAHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.OnlyMasterWrapper(w, r, false)
	_ = r.ParseForm()

	err := oAdmin.resetUserAuthApp(r.FormValue("username"))

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "2FA reseted")
	}
}

func (oAdmin *OvpnAdmin) UserStatisticHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	userStatistic, _ := json.Marshal(oAdmin.getUserStatistic(r.FormValue("username")))
	fmt.Fprintf(w, "%s", userStatistic)
}

func (oAdmin *OvpnAdmin) UserCreateHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.OnlyMasterWrapper(w, r, false)
	_ = r.ParseForm()
	userCreateStatus, userCreateErr := oAdmin.userCreate(r.FormValue("username"), r.FormValue("password"))

	if userCreateErr != nil {
		http.Error(w, userCreateStatus, http.StatusUnprocessableEntity)
	} else {
		oAdmin.clients = oAdmin.usersList()
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, userCreateStatus)
		return
	}
}
func (oAdmin *OvpnAdmin) UserRotateHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.OnlyMasterWrapper(w, r, false)
	_ = r.ParseForm()
	err, msg := oAdmin.userRotate(r.FormValue("username"), r.FormValue("password"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, msg)
	}
}

func (oAdmin *OvpnAdmin) UserDeleteHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.OnlyMasterWrapper(w, r, false)
	_ = r.ParseForm()
	err, msg := oAdmin.userDelete(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, msg)
	}
}

func (oAdmin *OvpnAdmin) UserRevokeHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.OnlyMasterWrapper(w, r, false)
	_ = r.ParseForm()
	err, msg := oAdmin.userRevoke(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, msg)
	}
}

func (oAdmin *OvpnAdmin) UserUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.OnlyMasterWrapper(w, r, false)
	_ = r.ParseForm()
	err, msg := oAdmin.userUnrevoke(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, msg)
	}
}

func (oAdmin *OvpnAdmin) UserChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	if *AuthByPassword {
		err, msg := oAdmin.userChangePassword(r.FormValue("username"), r.FormValue("password"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"status":"error", "message": "%s"}`, msg)

		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"ok", "message": "%s"}`, msg)
		}
	} else {
		http.Error(w, `{"status":"error"}`, http.StatusNotImplemented)
	}

}

func (oAdmin *OvpnAdmin) UserShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	fmt.Fprintf(w, "%s", oAdmin.renderClientConfig(r.FormValue("username")))
}

func (oAdmin *OvpnAdmin) UserDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	// 	fmt.Fprintf(w, "%s", userDisconnect(r.FormValue("username")))
	fmt.Fprintf(w, "%s", r.FormValue("username"))
}

func (oAdmin *OvpnAdmin) UserShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	ccd, _ := json.Marshal(oAdmin.getCcd(r.FormValue("username")))
	fmt.Fprintf(w, "%s", ccd)
}

func (oAdmin *OvpnAdmin) UserApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.OnlyMasterWrapper(w, r, false)
	var ccd CCD
	if r.Body == nil {
		http.Error(w, "Please send a request body", http.StatusBadRequest)
		return
	}

	err := json.NewDecoder(r.Body).Decode(&ccd)
	if err != nil {
		log.Errorln(err)
	}

	ccdApplied, applyStatus := oAdmin.modifyCcd(ccd)

	if ccdApplied {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, applyStatus)
		return
	} else {
		http.Error(w, applyStatus, http.StatusUnprocessableEntity)
	}
}

func (oAdmin *OvpnAdmin) ServerSettingsHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enabledModules, enabledModulesErr := json.Marshal(oAdmin.Modules)
	if enabledModulesErr != nil {
		log.Errorln(enabledModulesErr)
	}
	fmt.Fprintf(w, `{"status":"ok", "serverRole": "%s", "modules": %s }`, oAdmin.Role, string(enabledModules))
}

func (oAdmin *OvpnAdmin) LastSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	fmt.Fprint(w, oAdmin.LastSyncTime)
}

func (oAdmin *OvpnAdmin) LastSuccessfulSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	fmt.Fprint(w, oAdmin.LastSuccessfulSyncTime)
}

func (oAdmin *OvpnAdmin) DownloadCertsHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.OnlyMasterWrapper(w, r, false)
	if *StorageBackend == "kubernetes.secrets" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	token := r.Form.Get("token")

	if token != oAdmin.MasterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCerts()
	w.Header().Set("Content-Disposition", "attachment; filename="+certsArchiveFileName)
	http.ServeFile(w, r, certsArchivePath)
}

func (oAdmin *OvpnAdmin) DownloadCcdHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.OnlyMasterWrapper(w, r, false)
	if *StorageBackend == "kubernetes.secrets" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	token := r.Form.Get("token")

	if token != oAdmin.MasterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCcd()
	w.Header().Set("Content-Disposition", "attachment; filename="+ccdArchiveFileName)
	http.ServeFile(w, r, ccdArchivePath)
}

func (oAdmin *OvpnAdmin) OnlyMasterWrapper(w http.ResponseWriter, r *http.Request, d bool) {
	if d {
		log.Debug(r.RemoteAddr, " ", r.RequestURI)
	} else {
		log.Info(r.RemoteAddr, " ", r.RequestURI)
	}
	if oAdmin.Role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
}
