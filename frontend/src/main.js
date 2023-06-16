import Vue from 'vue';
import axios from 'axios';
import VueQr from 'vue-qr'
import VueCookies from 'vue-cookies'
import BootstrapVue from 'bootstrap-vue'
import Notifications from 'vue-notification'
import VueGoodTablePlugin from 'vue-good-table'

Vue.use(VueCookies)
Vue.use(BootstrapVue)
Vue.use(Notifications)
Vue.use(VueGoodTablePlugin)
Vue.use(VueQr)

let axios_cfg = function(url, data='', type='form') {
  if (data == '') {
    return {
      method: 'get',
      url: url
    };
  } else if (type == 'form') {
    return {
      method: 'post',
      url: url,
      data: data,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    };
  } else if (type == 'file') {
    return {
      method: 'post',
      url: url,
      data: data,
      headers: { 'Content-Type': 'multipart/form-data' }
    };
   } else if (type == 'json') {
    return {
      method: 'post',
      url: url,
      data: data,
      headers: { 'Content-Type': 'application/json' }
    };
  }
};

new Vue({
  el: '#app',
  data: {
    columns: [
      {
        label: 'Name',
        field: 'Identity',
        // filterable: true,
      },
      {
        label: 'Account Status',
        field: 'AccountStatus',
        filterable: true,
      },
      {
        label: 'Active Connections',
        field: 'Connections',
        filterable: true,
      },
      {
        label: 'Expiration Date',
        field: 'ExpirationDate',
        type: 'date',
        dateInputFormat: 'yyyy-MM-dd HH:mm:ss',
        dateOutputFormat: 'yyyy-MM-dd HH:mm:ss',
        formatFn: function (value) {
          return value != "" ? value : ""
        }
      },
      {
        label: 'Revocation Date',
        field: 'RevocationDate',
        type: 'date',
        dateInputFormat: 'yyyy-MM-dd HH:mm:ss',
        dateOutputFormat: 'yyyy-MM-dd HH:mm:ss',
        formatFn: function (value) {
          return value != "" ? value : ""
        }
      },
      {
        label: 'Actions',
        field: 'actions',
        sortable: false,
        tdClass: 'text-right',
        globalSearchDisabled: true,
      },
    ],
    rows: [],
    actions: [
      {
        name: 'u-change-password',
        label: 'Change password',
        class: 'btn-warning',
        showWhenStatus: 'Active',
        showForServerRole: ['master'],
        showForModule: ['passwdAuth'],
      },
      {
        name: 'u-2fa',
        label: '2FA',
        class: 'btn-success',
        showWhenStatus: 'Active',
        showForServerRole: ['master'],
        showForModule: ['totpAuth'],
      },
      {
        name: 'u-revoke',
        label: 'Revoke',
        class: 'btn-warning',
        showWhenStatus: 'Active',
        showForServerRole: ['master'],
        showForModule: ["core"],
      },
      {
        name: 'u-delete',
        label: 'Delete',
        class: 'btn-danger',
        showWhenStatus: 'Revoked',
        showForServerRole: ['master'],
        showForModule: ["core"],
      },
      {
        name: 'u-delete',
        label: 'Delete',
        class: 'btn-danger',
        showWhenStatus: 'Expired',
        showForServerRole: ['master'],
        showForModule: ["core"],
      },
      {
        name: 'u-rotate',
        label: 'Rotate',
        class: 'btn-warning',
        showWhenStatus: 'Revoked',
        showForServerRole: ['master'],
        showForModule: ["core"],
      },
      {
        name: 'u-rotate',
        label: 'Rotate',
        class: 'btn-warning',
        showWhenStatus: 'Expired',
        showForServerRole: ['master'],
        showForModule: ["core"],
      },
      {
        name: 'u-unrevoke',
        label: 'Unrevoke',
        class: 'btn-primary',
        showWhenStatus: 'Revoked',
        showForServerRole: ['master'],
        showForModule: ["core"],
      },
      {
        name: 'u-download-config',
        label: 'Download config',
        class: 'btn-info',
        showWhenStatus: 'Active',
        showForServerRole: ['master', 'slave'],
        showForModule: ["core"],
      },
      {
        name: 'u-edit-ccd',
        label: 'Edit routes',
        class: 'btn-primary',
        showWhenStatus: 'Active',
        showForServerRole: ['master'],
        showForModule: ["ccd"],
      },
      {
        name: 'u-edit-ccd',
        label: 'Show routes',
        class: 'btn-primary',
        showWhenStatus: 'Active',
        showForServerRole: ['slave'],
        showForModule: ["ccd"],
      }
    ],
    filters: {
      hideRevoked: true,
    },
    serverRole: "master",
    lastSync: "unknown",
    modulesEnabled: [],
    u: {
      newUserName: '',
      newUserPassword: '',
      newPassword: '',
      modalActionStatus: '',
      modalActionMessage: '',
      modalNewUserVisible: false,
      modalShowCcdVisible: false,
      modalChangePasswordVisible: false,
      modalRotateUserVisible: false,
      modalDeleteUserVisible: false,
      modalRegister2faVisible: false,
      openvpnConfig: '',
      secret: '',
      token: '',
      twofaurl: '',
      ccd: {
        Name: '',
        ClientAddress: '',
        CustomRoutes: []
      },
      newRoute: {},
    }
  },
  watch: {
  },
  mounted: function () {
    this.getUserData();
    this.getServerSetting();
    this.filters.hideRevoked = this.$cookies.isKey('hideRevoked') ? (this.$cookies.get('hideRevoked') == "true") : false
  },
  created() {
    let _this = this;

    _this.$root.$on('u-revoke', function (msg) {
      let data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/revoke', data, 'form'))
      .then(function(response) {
        _this.getUserData();
        _this.$notify({title: 'User ' + _this.username + ' revoked!', type: 'warn'})
      }).catch(function(error) {
        console.error()
        _this.$notify({title: 'Failed to revoke user ' + _this.username , type: 'error'})
      });
    })
    _this.$root.$on('u-unrevoke', function () {
      let data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/unrevoke', data, 'form'))
      .then(function(response) {
        _this.getUserData();
        _this.$notify({title: 'User ' + _this.username + ' unrevoked!', type: 'success'})
      }).catch(function(error) {
        console.error()
        _this.$notify({title: 'Failed to unrevoke user ' + _this.username , type: 'error'})
      });
    })
    _this.$root.$on('u-rotate', function () {
      _this.u.modalRotateUserVisible = true;
      let data = new URLSearchParams();
      data.append('username', _this.username);
    })
    _this.$root.$on('u-delete', function () {
      _this.u.modalDeleteUserVisible = true;
      let data = new URLSearchParams();
      data.append('username', _this.username);
    })
    _this.$root.$on('u-download-config', function () {
      let data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/config/show', data, 'form'))
      .then(function(response) {
        const blob = new Blob([response.data], { type: 'text/plain' })
        const link = document.createElement('a')
        link.href = URL.createObjectURL(blob)
        link.download = _this.username + ".ovpn"
        link.click()
        URL.revokeObjectURL(link.href)
      }).catch(function(error) {
        console.error()
        _this.$notify({title: 'Failed to download config for user ' + _this.username , type: 'error'})
      });
    })
    _this.$root.$on('u-edit-ccd', function () {
      _this.u.modalShowCcdVisible = true;
      let data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/ccd', data, 'form'))
      .then(function(response) {
        _this.u.ccd = response.data;
      });
    })
    _this.$root.$on('u-disconnect-user', function () {
      _this.u.modalShowCcdVisible = true;
      let data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/disconnect', data, 'form'))
      .then(function(response) {
        console.log(response.data);
      });
    })
    _this.$root.$on('u-change-password', function () {
      _this.u.modalChangePasswordVisible = true;
      let data = new URLSearchParams();
      data.append('username', _this.username);
    })
    _this.$root.$on('u-2fa', function () {
      _this.u.modalRegister2faVisible = true;
      let data = new URLSearchParams();
      data.append('username', _this.username);
      data.append('secondfactor', _this.secondfactor);
      data.append('token', _this.token);
      _this.getUserTFAData(data);
    })
  },
  computed: {
    customAddressDynamic: function () {
      return this.u.ccd.ClientAddress == "dynamic"
    },
    alertCssClass: function () {
      return this.u.modalActionStatus == 200 ? "alert-success" : "alert-danger"
    },
    revokeFilterText: function() {
      return this.filters.hideRevoked ? "Show revoked" : "Hide revoked"
    },
    filteredRows: function() {
      if (this.filters.hideRevoked) {
        return this.rows.filter(function(account) {
          return account.AccountStatus == "Active"
        });
      } else {
        return this.rows
      }
    }
},
  methods: {
    rowStyleClassFn: function(row) {
      if (row.ConnectionStatus == 'Connected') {
        return 'connected-user'
      }
      if (row.AccountStatus == 'Revoked') {
        return 'revoked-user'
      }
      if (row.AccountStatus == 'Expired') {
        return 'expired-user'
      }
      return ''
    },

    rowActionFn: function(e) {
      this.username = e.target.dataset.username;
      this.secondfactor = e.target.dataset.secondfactor;

      this.$root.$emit(e.target.dataset.name);
    },

    getUserData: function() {
      let _this = this;
      axios.request(axios_cfg('api/users/list'))
        .then(function(response) {
          _this.rows = Array.isArray(response.data) ? response.data : [];
        });
    },

    getUserTFAData: function(data) {
      let _this = this;
      if (!_this.secondfactor) {
        axios.request(axios_cfg('api/user/2fa/secret', data, 'form'))
          .then(function (response) {
            _this.u.secret = response.data;
            _this.u.twofaurl = "otpauth://totp/ovpn-" + _this.username + "?secret=" + _this.u.secret + "&issuer=OVPN";
          });
      }
    },

    registerUser2faApp: function(username) {
      let _this = this;

      let data = new URLSearchParams();
      data.append('username', username);
      data.append('token', _this.u.token);

      axios.request(axios_cfg('api/user/2fa/register', data, 'form'))
        .then(function(response) {
          _this.u.modalActionStatus = 200;
          _this.u.modalRegister2faVisible = false;
          _this.getUserData();
          _this.secondfactor = true;
          _this.u.token = "";
          _this.u.secret = "";
          _this.$notify({title: '2FA application registered  for user ' + username, type: 'success'});
        })
        .catch(function(error) {
          _this.u.modalActionStatus = error.response.status;
          _this.u.modalActionMessage = error.response.data.message;
          _this.$notify({title: 'Register 2FA application for user ' + username + ' failed!', type: 'error'});
        })
    },

    resetUser2faApp: function(username) {
      let _this = this;

      let data = new URLSearchParams();
      data.append('username', username);
      data.append('secondfactor', _this.secondfactor);

      axios.request(axios_cfg('api/user/2fa/reset', data, 'form'))
        .then(function(response) {
          _this.u.modalActionStatus = 200;
          _this.secondfactor = false;
          _this.getUserTFAData(data);
          _this.getUserData();
          _this.$notify({title: '2FA application reset for user ' + username, type: 'success'});
        })
        .catch(function(error) {
          _this.u.modalActionStatus = error.response.status;
          _this.u.modalActionMessage = error.response.data.message;
          _this.$notify({title: 'Reset 2FA application for user ' + username + ' failed!', type: 'error'});
        })
    },

    getServerSetting: function() {
      let _this = this;
      axios.request(axios_cfg('api/server/settings'))
      .then(function(response) {
        _this.serverRole = response.data.serverRole;
        _this.modulesEnabled = response.data.modules;

        if (_this.serverRole == "slave") {
          axios.request(axios_cfg('api/sync/last/successful'))
          .then(function(response) {
            _this.lastSync =  response.data;
          });
        }
      });
    },

    createUser: function() {
      let _this = this;

      _this.u.modalActionMessage = "";

      let data = new URLSearchParams();
      data.append('username', _this.u.newUserName);
      data.append('password', _this.u.newUserPassword);

      _this.username = _this.u.newUserName;

      axios.request(axios_cfg('api/user/create', data, 'form'))
      .then(function(response) {
        _this.$notify({title: 'New user ' + _this.username + ' created', type: 'success'});
        _this.u.modalNewUserVisible = false;
        _this.u.newUserName = '';
        _this.u.newUserPassword = '';
        _this.getUserData();
      })
      .catch(function(error) {
        _this.u.modalActionMessage = error.response.data;
        _this.$notify({title: 'New user ' + _this.username + ' creation failed.', type: 'error'});

      });
    },

    ccdApply: function() {
      let _this = this;

      _this.u.modalActionStatus= "";
      _this.u.modalActionMessage = "";

      axios.request(axios_cfg('api/user/ccd/apply', JSON.stringify(_this.u.ccd), 'json'))
      .then(function(response) {
        _this.u.modalActionStatus = 200;
        _this.u.modalActionMessage = response.data;
        _this.$notify({title: 'New CCD for user ' + _this.username + ' applied', type: 'success'});
      })
      .catch(function(error) {
        _this.u.modalActionStatus = error.response.status;
        _this.u.modalActionMessage = error.response.data.message;
        _this.$notify({title: 'Apply new CCD for user ' + _this.username + 'failed ', type: 'error'});
      });
    },

    changeUserPassword: function(username) {
      let _this = this;

      _this.u.modalActionMessage = "";

      let data = new URLSearchParams();
      data.append('username', username);
      data.append('password', _this.u.newPassword);

      axios.request(axios_cfg('api/user/change-password', data, 'form'))
        .then(function(response) {
          _this.u.modalActionStatus = 200;
          _this.u.newPassword = '';
          _this.getUserData();
          _this.u.modalChangePasswordVisible = false;
          _this.$notify({title: 'Password for user ' + username + ' changed!', type: 'success'});
        })
        .catch(function(error) {
          _this.u.modalActionStatus = error.response.status;
          _this.u.modalActionMessage = error.response.data.message;
          _this.$notify({title: 'Changing password for user ' + username + ' failed!', type: 'error'});
        });
    },

    rotateUser: function(username) {
      let _this = this;

      _this.u.modalActionMessage = "";

      let data = new URLSearchParams();
      data.append('username', username);
      data.append('password', _this.u.newPassword);

      axios.request(axios_cfg('api/user/rotate', data, 'form'))
        .then(function(response) {
          _this.u.modalActionStatus = 200;
          _this.u.newPassword = '';
          _this.getUserData();
          _this.u.modalRotateUserVisible = false;
          _this.$notify({title: 'Certificates for user ' + username + ' rotated!', type: 'success'});
        })
        .catch(function(error) {
          _this.u.modalActionStatus = error.response.status;
          _this.u.modalActionMessage = error.response.data.message;
          _this.$notify({title: 'Rotate certificates for user ' + username + ' failed!', type: 'error'});
        })
    },

    deleteUser: function(username) {
      let _this = this;

      _this.u.deleteUserMessage = "";

      let data = new URLSearchParams();
      data.append('username', username);

      axios.request(axios_cfg('api/user/delete', data, 'form'))
        .then(function(response) {
          _this.u.modalActionStatus = 200;
          _this.u.newPassword = '';
          _this.getUserData();
          _this.u.modalDeleteUserVisible = false;
          _this.$notify({title: 'User ' + username + ' deleted!', type: 'success'});
        })
        .catch(function(error) {
          _this.u.modalActionStatus = error.response.status;
          _this.u.modalActionMessage = error.response.data.message;
          _this.$notify({title: 'Deleting user ' + username + ' failed!', type: 'error'});
        })
    },
  }

})
