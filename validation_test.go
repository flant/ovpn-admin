package main

import (
	"testing"
)

func Test_validator_validateUsername(t *testing.T) {
	type args struct {
		username string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "success (qwerty)",
			args:    args{"qwerty"},
			wantErr: false,
		},
		{
			name:    "success (qwerty@gmail.com)",
			args:    args{"qwerty@gmail.com"},
			wantErr: false,
		},
		{
			name:    "success (luck.cage)",
			args:    args{"luck.cage"},
			wantErr: false,
		},
		{
			name:    "error (empty)",
			args:    args{""},
			wantErr: true,
		},
		{
			name:    "error (/bin/bash)",
			args:    args{"/bin/bash"},
			wantErr: true,
		},
		{
			name:    "error (./exploit.sh)",
			args:    args{"./exploit.sh"},
			wantErr: true,
		},
		{
			name:    "error (rm rf /)",
			args:    args{"rm rf /"},
			wantErr: true,
		},
		{
			name:    "error (; ls)",
			args:    args{"; ls"},
			wantErr: true,
		},
		{
			name:    "error (&echo>passwd)",
			args:    args{"&echo>passwd"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := newValidator()
			if err != nil {
				t.Error(err)
			}
			if err := v.validateUsername(tt.args.username); (err != nil) != tt.wantErr {
				t.Errorf("validateUsername() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validator_validatePassword(t *testing.T) {
	type args struct {
		passwd string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{

		{
			name:    "success (qwe1239%$0123924qw)",
			args:    args{"qwe1239%$0123924qw"},
			wantErr: false,
		},
		{
			name:    "success (pa$$w0rd)",
			args:    args{"pa$$w0rd"},
			wantErr: false,
		},
		{
			name:    "short (qwe)",
			args:    args{"qwe"},
			wantErr: true,
		},
		{
			name:    "error (empty)",
			args:    args{""},
			wantErr: true,
		},
		{
			name:    "error (/bin/bash)",
			args:    args{"/bin/bash"},
			wantErr: true,
		},
		{
			name:    "error (./exploit.sh)",
			args:    args{"./exploit.sh"},
			wantErr: true,
		},
		{
			name:    "error (rm rf /)",
			args:    args{"rm rf /"},
			wantErr: true,
		},
		{
			name:    "error (; ls)",
			args:    args{"; ls"},
			wantErr: true,
		},
		{
			name:    "error (&echo>passwd)",
			args:    args{"&echo>passwd"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := newValidator()
			if err != nil {
				t.Error(err)
			}
			if err := v.validatePassword(tt.args.passwd); (err != nil) != tt.wantErr {
				t.Errorf("validatePassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
