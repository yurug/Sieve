package gmail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	calendarapi "google.golang.org/api/calendar/v3"
	driveapi "google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

func newCalendarClient(t *testing.T, handler http.HandlerFunc) *CalendarClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	svc, err := calendarapi.NewService(context.Background(),
		option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("calendar NewService: %v", err)
	}
	return NewCalendarClient(svc)
}

func newDriveClient(t *testing.T, handler http.HandlerFunc) *DriveClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	svc, err := driveapi.NewService(context.Background(),
		option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("drive NewService: %v", err)
	}
	return NewDriveClient(svc)
}

func ptr(s string) *string { return &s }

// TestUpdateEvent_ClearsAndLeaves proves the presence-aware patch: a field set
// to "" is CLEARED on the wire (previously a silent no-op), a field that's set
// is updated, and an omitted field is not sent at all (left unchanged).
func TestUpdateEvent_ClearsAndLeaves(t *testing.T) {
	var body map[string]any
	c := newCalendarClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(&calendarapi.Event{Id: "e1"})
	})

	_, err := c.UpdateEvent(context.Background(), "primary", "e1", EventPatch{
		Summary:  ptr("New title"),
		Location: ptr(""), // explicit clear
		// Description omitted → must not appear in the request.
	})
	if err != nil {
		t.Fatalf("UpdateEvent: %v", err)
	}
	if body["summary"] != "New title" {
		t.Errorf("summary = %v, want it updated", body["summary"])
	}
	loc, ok := body["location"]
	if !ok || loc != "" {
		t.Errorf("location = %v (present=%v), want a present empty string (cleared via ForceSendFields)", loc, ok)
	}
	if _, present := body["description"]; present {
		t.Errorf("description was sent (%v) but was omitted by the caller — must be left unchanged", body["description"])
	}
}

// TestUpdateEvent_ReplacesAttendees proves attendees, when present, replaces the
// whole list (Google PATCH semantics — the connector op documents this).
func TestUpdateEvent_ReplacesAttendees(t *testing.T) {
	var body map[string]any
	c := newCalendarClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(&calendarapi.Event{Id: "e1"})
	})
	att := []string{"new@example.com"}
	_, err := c.UpdateEvent(context.Background(), "primary", "e1", EventPatch{Attendees: &att})
	if err != nil {
		t.Fatalf("UpdateEvent: %v", err)
	}
	list, ok := body["attendees"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("attendees = %v, want one entry", body["attendees"])
	}
	if m, _ := list[0].(map[string]any); m["email"] != "new@example.com" {
		t.Errorf("attendee = %v, want new@example.com", list[0])
	}
}

// TestShareFile_TypeAndNotification proves type and send_notification are now
// caller-controlled (previously hardcoded type=user, notification=true).
func TestShareFile_TypeAndNotification(t *testing.T) {
	var perm map[string]any
	var sendNotif string
	c := newDriveClient(t, func(w http.ResponseWriter, r *http.Request) {
		sendNotif = r.URL.Query().Get("sendNotificationEmail")
		_ = json.NewDecoder(r.Body).Decode(&perm)
		json.NewEncoder(w).Encode(&driveapi.Permission{Id: "p1", Type: "anyone", Role: "reader"})
	})

	_, err := c.ShareFile(context.Background(), "file-1", ShareSpec{
		Type:             "anyone",
		Role:             "reader",
		SendNotification: false,
	})
	if err != nil {
		t.Fatalf("ShareFile: %v", err)
	}
	if perm["type"] != "anyone" {
		t.Errorf("permission type = %v, want anyone", perm["type"])
	}
	if _, hasEmail := perm["emailAddress"]; hasEmail {
		t.Errorf("type=anyone must not carry an emailAddress: %v", perm)
	}
	if sendNotif != "false" {
		t.Errorf("sendNotificationEmail = %q, want false", sendNotif)
	}
}
