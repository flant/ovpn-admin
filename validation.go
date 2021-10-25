package main

import (
	"fmt"
	"net"
	"regexp"
	"unicode/utf8"
)

const (
	usernameRegexp       = `^[a-zA-Z0-9@]+([._]?[a-zA-Z0-9]+)*$`
	passwordRegexp       = `^[a-zA-Z0-9@$!#%^_\-]+([._]?[a-zA-Z0-9]+)*$`
	CCDDescriptionRegexp = `^[a-zA-Z0-9 ]*$`
	usernameMinLength    = 3
	passwordMinLength    = 6
)

type (
	validator interface {
		validateUsername(string) error
		validatePassword(string) error
		validateCCD(ccd CCD) error
	}

	validators struct {
		reUserName       *regexp.Regexp
		rePassword       *regexp.Regexp
		reCCDDescription *regexp.Regexp
	}
)

func (v *validators) validateCCD(ccd CCD) error {
	if err := v.validateUsername(ccd.User); err != nil {
		return err
	}

	if ccd.ClientAddress != "dynamic" {
		if net.ParseIP(ccd.ClientAddress) == nil {
			return fmt.Errorf("invalid ClientAddress")
		}
	}

	for _, route := range ccd.CustomRoutes {
		if net.ParseIP(route.Address) == nil {
			return fmt.Errorf("invalid CustomRoute.Address")
		}
		if net.ParseIP(route.Mask) == nil {
			return fmt.Errorf("invalid CustomRoute.Mask")
		}
		if utf8.RuneCountInString(route.Description) > 0 && !v.reCCDDescription.MatchString(route.Description) {
			return fmt.Errorf("invalid CustomRoute.Description")
		}
	}
	return nil
}

func newValidator() (validator, error) {
	reUsername, err := regexp.Compile(usernameRegexp)
	if err != nil {
		return nil, fmt.Errorf("username regexp compile failed %s", err)
	}
	rePassword, err := regexp.Compile(passwordRegexp)
	if err != nil {
		return nil, fmt.Errorf("password regexp compile failed %s", err)
	}
	reCCDDescription, err := regexp.Compile(CCDDescriptionRegexp)
	if err != nil {
		return nil, fmt.Errorf("ccd desctiprion regexp compile failed %s", err)
	}
	return &validators{
		reUserName:       reUsername,
		rePassword:       rePassword,
		reCCDDescription: reCCDDescription,
	}, nil
}

func (v *validators) validateUsername(username string) error {
	if usernameMinLength > utf8.RuneCountInString(username) || !v.reUserName.MatchString(username) {
		return fmt.Errorf("invalid username")
	}
	return nil
}

func (v *validators) validatePassword(passwd string) error {
	if passwordMinLength > utf8.RuneCountInString(passwd) || !v.rePassword.MatchString(passwd) {
		return fmt.Errorf("invalid password")
	}
	return nil
}
